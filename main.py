import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import re
import time

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Referer': 'https://mtgtop8.com/format?f=PAU'
}
BASE_URL = 'https://mtgtop8.com/'

session = requests.Session()
session.headers.update(HEADERS)

def extrair_visao_macro(soup):
    """
    1. Extrai o dicionário MACRO (AGGRO, CONTROL, COMBO) e os links de cada arquétipo.
    """
    macro_dict = {}
    archetype_links = []
    current_macro = None
    
    elementos = soup.find_all(
        lambda tag: tag.name == 'div' and (
            'meta_arch' in tag.get('class', []) or 
            ('hover_tr' in tag.get('class', []) and tag.find('a', href=re.compile(r'^archetype\?')))
        )
    )
    
    for el in elementos:
        if 'meta_arch' in el.get('class', []):
            texto = el.get_text(strip=True)
            match = re.match(r'^([A-Za-z]+)', texto)
            if match:
                current_macro = match.group(1).upper()
                if current_macro not in macro_dict:
                    macro_dict[current_macro] = []
        else:
            if not current_macro:
                continue
            a_tag = el.find('a', href=re.compile(r'^archetype\?'))
            if a_tag:
                nome_deck = a_tag.get_text(strip=True)
                href = a_tag['href']
                
                s14_divs = el.find_all('div', class_='S14')
                percentual = "0%"
                for div in s14_divs:
                    txt = div.get_text(strip=True)
                    if '%' in txt:
                        percentual = txt.replace(' ', '')
                        break
                
                macro_dict[current_macro].append((nome_deck, percentual))
                archetype_links.append((current_macro, nome_deck, href))
                
    return macro_dict, archetype_links


def extrair_cartas_deck_mtgo(deck_id):
    """
    Extrai as 75 cartas exatas do deck usando o exportador de texto do MTGTop8 (mtgo?d=ID).
    Garante que todas as cartas (Lands, Creatures, Spells e Sideboard) venham completas.
    """
    url = f"{BASE_URL}mtgo?d={deck_id}"
    resp = session.get(url)
    cartas = {}
    
    if resp.status_code == 200:
        for linha in resp.text.splitlines():
            linha = linha.strip()
            # Ignora linha vazia ou cabeçalho "Sideboard"
            if not linha or linha.lower().startswith('sideboard'):
                continue
            # Exemplo: "4 Lightning Bolt"
            match = re.match(r'^(\d+)\s+(.+)$', linha)
            if match:
                qtd = int(match.group(1))
                nome_carta = match.group(2).strip()
                # Soma se a carta estiver no Maindeck e também no Sideboard (máximo 4 cópias)
                cartas[nome_carta] = cartas.get(nome_carta, 0) + qtd
                
    return cartas


def montar_chave_unica(player_name, event_name, date_str, chaves_existentes):
    """
    Gera a chave no formato: 'yahakara | MTGO Challenge | 17/10'
    Se houver colisão exata (ex: nick genérico no mesmo torneio), adiciona '#2', '#3', etc.
    """
    # Corta o ano se vier no formato DD/MM/AA (ex: '17/10/26' -> '17/10')
    partes_data = date_str.split('/')
    data_curta = f"{partes_data[0]}/{partes_data[1]}" if len(partes_data) >= 2 else date_str
    
    chave_base = f"{player_name} | {event_name} | {data_curta}"
    chave_final = chave_base
    contador = 2
    
    while chave_final in chaves_existentes:
        chave_final = f"{chave_base} #{contador}"
        contador += 1
        
    return chave_final


def extrair_arquetipo(macro_cat, arch_name, arch_url, decks_ja_vistos, chaves_existentes):
    """
    2. Navega pelas páginas do arquétipo, monta a Tabela 1 e extrai as cartas para a Tabela 2.
    """
    tabela1_linhas = []
    dicionario_decks_cartas = {}
    pagina_atual = 1
    
    while True:
        url = f"{BASE_URL}{arch_url}&current_page={pagina_atual}"
        print(f"  -> Extraindo [{macro_cat}] {arch_name} - Página {pagina_atual}...")
        
        # Envia current_page também via POST para garantir a paginação do PageSubmit_arch
        resp = session.post(url, data={'current_page': str(pagina_atual)})
        if resp.status_code != 200:
            break
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        form = soup.find('form', attrs={'name': 'compare_decks'})
        if not form:
            break
            
        linhas_tr = form.find_all('tr', class_='hover_tr')
        if not linhas_tr:
            break
            
        novos_decks_na_pagina = 0
        
        for tr in linhas_tr:
            tds = tr.find_all('td')
            if len(tds) < 7:
                continue
                
            hidden = tds[0].find('input', attrs={'type': 'hidden'})
            if not hidden:
                continue
                
            deck_id = hidden.get('value', '').strip()
            
            # Se o deck_id já foi extraído antes, pula para não duplicar!
            if not deck_id or deck_id in decks_ja_vistos:
                continue
                
            decks_ja_vistos.add(deck_id)
            novos_decks_na_pagina += 1
            
            deck_name = tds[1].get_text(strip=True)
            player_name = tds[2].get_text(strip=True)
            event_name = tds[3].get_text(strip=True)
            rank = tds[5].get_text(strip=True)
            date_full = tds[6].get_text(strip=True)
            
            # Cria o ID no formato: "yahakara | MTGO Challenge | 17/10"
            col_key = montar_chave_unica(player_name, event_name, date_full, chaves_existentes)
            chaves_existentes.add(col_key)
            
            tabela1_linhas.append({
                'Player_ID': col_key,         # Chave igual à coluna da Tabela 2
                'Archetype': macro_cat,       # AGGRO, CONTROL, COMBO
                'Macro_Deck': arch_name,      # Affinity, Dimir Control, etc.
                'Deck': deck_name,            # Grixis Affinity, Esper Affinity, etc.
                'Player': player_name,
                'Event': event_name,
                'Rank': rank,
                'Date': date_full
            })
            
            # Extrai as 75 cartas deste deck
            time.sleep(0.2)
            cartas_do_deck = extrair_cartas_deck_mtgo(deck_id)
            if cartas_do_deck:
                dicionario_decks_cartas[col_key] = cartas_do_deck
                
        # Se nenhum deck novo apareceu na página, encerramos a paginação deste arquétipo
        if novos_decks_na_pagina == 0:
            break
            
        proxima_pag = pagina_atual + 1
        tem_proxima = soup.find('div', class_='Nav_norm', onclick=re.compile(rf'PageSubmit_arch\({proxima_pag}\)'))
        if tem_proxima:
            pagina_atual = proxima_pag
            time.sleep(0.5)
        else:
            break
            
    return tabela1_linhas, dicionario_decks_cartas


def main():
    print("Acessando página principal do Pauper...")
    resp = session.get(f"{BASE_URL}format?f=PAU")
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    # 1. Extrair JSON Macro
    macro_dict, archetype_links = extrair_visao_macro(soup)
    
    with open('meta_macro_pauper.json', 'w', encoding='utf-8') as f:
        json.dump(macro_dict, f, ensure_ascii=False, indent=4)
    print("Arquivo 'meta_macro_pauper.json' salvo com sucesso!")
        
    todas_linhas_tabela1 = []
    todos_decks_tabela2 = {}
    
    # Sets globais para garantir zero duplicidade entre páginas ou arquétipos
    decks_ja_vistos = set()
    chaves_existentes = set()
    
    # 2. Percorrer cada arquétipo
    for macro_cat, arch_name, arch_url in archetype_links:
        linhas_t1, decks_t2 = extrair_arquetipo(
            macro_cat, arch_name, arch_url, decks_ja_vistos, chaves_existentes
        )
        todas_linhas_tabela1.extend(linhas_t1)
        todos_decks_tabela2.update(decks_t2)
            
    # 3. Salvar Tabela 1
    df_tabela1 = pd.DataFrame(todas_linhas_tabela1)
    df_tabela1.to_csv('tabela1_decks_pauper.csv', index=False, encoding='utf-8-sig')
    print(f"\nTabela 1 gerada! Total de participações/decks únicos: {len(df_tabela1)}")
    
    # 4. Salvar Tabela 2
    if todos_decks_tabela2:
        df_tabela2 = pd.DataFrame.from_dict(todos_decks_tabela2, orient='columns').fillna(0).astype(int)
        df_tabela2.index.name = 'Card'
        df_tabela2 = df_tabela2.sort_index()
        df_tabela2.to_csv('tabela2_cartas_por_jogador.csv', encoding='utf-8-sig')
        print(f"Tabela 2 gerada! Dimensões: {df_tabela2.shape[0]} cartas x {df_tabela2.shape[1]} colunas.")

if __name__ == '__main__':
    main()