import os
import re
import json
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import pandas as pd
from threat_dict import aplicar_threat_type

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Referer': 'https://mtgtop8.com/format?f=PAU'
}
BASE_URL = 'https://mtgtop8.com/'

# Configura sessão com Retry Automático (evita que o script quebre se o site oscilar)
def criar_sessao():
    s = requests.Session()
    s.headers.update(HEADERS)
    retry_strategy = Retry(
        total=5,
        backoff_factor=1.5, # Espera 1.5s, 3s, 6s... se o servidor demorar
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

session = criar_sessao()

def req_segura(metodo, url, **kwargs):
    """Wrapper com timeout e múltiplas tentativas contra WinError 10060 / ReadTimeout."""
    kwargs.setdefault('timeout', 30)
    for tentativa in range(1, 5):
        try:
            if metodo == 'GET':
                return session.get(url, **kwargs)
            else:
                return session.post(url, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"    [Aviso] Oscilação de rede ({e.__class__.__name__}). Tentativa {tentativa}/4...")
            time.sleep(3 * tentativa)
    return None


def extrair_visao_macro(soup):
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


def parse_compare_decks_completo(html_compare, ordered_player_keys, todos_decks_tabela2, dict_categorias_tabela3):
    """
    Extrai simultaneamente da aba 'Compare Decks':
    - As quantidades de cada carta por jogador (Tabela 2)
    - A categoria de cada carta: LANDS, CREATURES, OTHER SPELLS, SIDEBOARDS (Tabela 3)
    """
    soup = BeautifulSoup(html_compare, 'html.parser')
    current_category = "UNKNOWN"
    
    valid_categories = {
        'LANDS', 'CREATURES', 'OTHER SPELLS', 'INSTANTS and SORC.', 
        'ARTIFACTS', 'ENCHANTMENTS', 'PLANESWALKERS', 'SIDEBOARDS'
    }
    
    num_players = len(ordered_player_keys)
    
    for tr in soup.find_all('tr'):
        tds = tr.find_all('td', recursive=False)
        if not tds:
            continue
            
        # 1. Verifica se é uma linha divisória de Categoria (ex: <tr><td align="center" width="250">LANDS</td></tr>)
        # Ignora o bloco de resumo do topo que tem class="S12"
        primeiro_td = tds[0]
        texto_td = primeiro_td.get_text(strip=True)
        if texto_td in valid_categories and 'S12' not in primeiro_td.get('class', []):
            current_category = texto_td
            continue
            
        # 2. Verifica se é uma linha de Carta (possui <div class="c2">Nome da Carta</div>)
        c2_div = primeiro_td.find('div', class_='c2')
        if c2_div:
            card_name = c2_div.get_text(strip=True)
            if not card_name:
                continue
                
            # Atualiza a Tabela 3 (Dicionário de Categorias)
            # Se a carta já foi vista no Maindeck (ex: CREATURES ou OTHER SPELLS), não sobrescreve com SIDEBOARDS
            if card_name not in dict_categorias_tabela3 or (
                dict_categorias_tabela3[card_name] == 'SIDEBOARDS' and current_category != 'SIDEBOARDS'
            ):
                dict_categorias_tabela3[card_name] = current_category
                
            # Atualiza a Tabela 2 (Quantidades por Jogador)
            # Estrutura do Compare Decks: td[0] = Nome da Carta | td[1] = Média (c_avg) | td[2:] = Quantidade de cada deck
            tds_jogadores = tds[2 : 2 + num_players]
            
            for player_key, td_qty in zip(ordered_player_keys, tds_jogadores):
                if player_key is None:
                    continue # Deck que já havia sido processado em outra página
                txt_qty = td_qty.get_text(strip=True)
                if txt_qty.isdigit():
                    qtd = int(txt_qty)
                    if qtd > 0:
                        if player_key not in todos_decks_tabela2:
                            todos_decks_tabela2[player_key] = {}
                        # Soma caso a carta apareça no Maindeck e também no Sideboard do mesmo jogador
                        todos_decks_tabela2[player_key][card_name] = (
                            todos_decks_tabela2[player_key].get(card_name, 0) + qtd
                        )


def montar_chave_unica(player_name, event_name, date_str, chaves_existentes):
    partes_data = date_str.split('/')
    data_curta = f"{partes_data[0]}/{partes_data[1]}" if len(partes_data) >= 2 else date_str
    
    chave_base = f"{player_name} | {event_name} | {data_curta}"
    chave_final = chave_base
    contador = 2
    
    while chave_final in chaves_existentes:
        chave_final = f"{chave_base} #{contador}"
        contador += 1
        
    return chave_final


def extrair_arquetipo(macro_cat, arch_name, arch_url, decks_ja_vistos, chaves_existentes, todos_decks_tabela2, dict_categorias_tabela3):
    tabela1_linhas = []
    pagina_atual = 1
    
    while True:
        url = f"{BASE_URL}{arch_url}&current_page={pagina_atual}"
        print(f"  -> Extraindo [{macro_cat}] {arch_name} - Página {pagina_atual}...")
        
        resp = req_segura('POST', url, data={'current_page': str(pagina_atual)})
        if not resp or resp.status_code != 200:
            break
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        form = soup.find('form', attrs={'name': 'compare_decks'})
        if not form:
            break
            
        linhas_tr = form.find_all('tr', class_='hover_tr')
        if not linhas_tr:
            break
            
        novos_decks_na_pagina = 0
        payload_compare = {}
        ordered_player_keys = [] # Mantém a ordem exata das colunas do Compare Decks
        
        for tr in linhas_tr:
            tds = tr.find_all('td')
            if len(tds) < 7:
                continue
                
            checkbox = tds[0].find('input', attrs={'type': 'checkbox'})
            hidden = tds[0].find('input', attrs={'type': 'hidden'})
            
            if not hidden:
                continue
                
            deck_id = hidden.get('value', '').strip()
            if not deck_id:
                continue
                
            # Preenche o payload para enviar ao Compare Decks
            if checkbox and hidden:
                payload_compare[checkbox.get('name', '')] = checkbox.get('value', '1')
                payload_compare[hidden.get('name', '')] = deck_id
                
            # Se o deck já foi visto antes, colocamos None na posição dele para não duplicar
            if deck_id in decks_ja_vistos:
                ordered_player_keys.append(None)
                continue
                
            decks_ja_vistos.add(deck_id)
            novos_decks_na_pagina += 1
            
            deck_name = tds[1].get_text(strip=True)
            player_name = tds[2].get_text(strip=True)
            event_name = tds[3].get_text(strip=True)
            rank = tds[5].get_text(strip=True)
            date_full = tds[6].get_text(strip=True)
            
            col_key = montar_chave_unica(player_name, event_name, date_full, chaves_existentes)
            chaves_existentes.add(col_key)
            ordered_player_keys.append(col_key)
            
            tabela1_linhas.append({
                'Player_ID': col_key,
                'Macro_Archetype': macro_cat,
                'Archetype': arch_name,
                'Sub_Archetype': deck_name,
                'Player': player_name,
                'Event': event_name,
                'Rank': rank,
                'Date': date_full
            })
            
        if novos_decks_na_pagina == 0:
            break
            
        # Faz APENAS 1 requisição para o Compare Decks da página inteira (muito mais rápido!)
        if payload_compare:
            compare_url = f"{BASE_URL}compare"
            time.sleep(0.4)
            resp_compare = req_segura('POST', compare_url, data=payload_compare)
            if resp_compare and resp_compare.status_code == 200:
                parse_compare_decks_completo(
                    resp_compare.text, 
                    ordered_player_keys, 
                    todos_decks_tabela2, 
                    dict_categorias_tabela3
                )
                
        proxima_pag = pagina_atual + 1
        tem_proxima = soup.find('div', class_='Nav_norm', onclick=re.compile(rf'PageSubmit_arch\({proxima_pag}\)'))
        if tem_proxima:
            pagina_atual = proxima_pag
            time.sleep(0.4)
        else:
            break
            
    return tabela1_linhas


def carregar_tabela3_existente(caminho_csv):
    """
    Carrega a Tabela 3 caso ela já exista no computador para nunca perder cartas antigas
    e manter o mesmo Card_ID entre execuções.
    """
    dict_categorias = {}
    dict_ids = {}
    proximo_id = 1
    
    if os.path.exists(caminho_csv):
        try:
            df_existente = pd.read_csv(caminho_csv)
            for _, row in df_existente.iterrows():
                card = str(row['Card'])
                cat = str(row['Category'])
                cid = int(row['Card_ID'])
                dict_categorias[card] = cat
                dict_ids[card] = cid
                if cid >= proximo_id:
                    proximo_id = cid + 1
            print(f"Tabela 3 existente carregada ({len(dict_categorias)} cartas já cadastradas).")
        except Exception as e:
            print(f"Aviso ao ler Tabela 3 antiga: {e}. Criando uma nova.")
            
    return dict_categorias, dict_ids, proximo_id


def main():
    print("Acessando página principal do Pauper...")
    resp = req_segura('GET', f"{BASE_URL}format?f=PAU")
    if not resp:
        print("Erro ao acessar o MTGTop8. Verifique sua conexão.")
        return
        
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    # 1. Extrair e salvar JSON Macro
    macro_dict, archetype_links = extrair_visao_macro(soup)
    with open('meta_macro_pauper.json', 'w', encoding='utf-8') as f:
        json.dump(macro_dict, f, ensure_ascii=False, indent=4)
    print("Arquivo 'meta_macro_pauper.json' atualizado!")
        
    # 2. Carregar Tabela 3 existente (incremental, sem sobrescrever cartas antigas)
    arquivo_tabela3 = 'tabela3_categorias_cartas.csv'
    dict_categorias_tabela3, dict_card_ids, proximo_id = carregar_tabela3_existente(arquivo_tabela3)
    
    todas_linhas_tabela1 = []
    todos_decks_tabela2 = {}
    decks_ja_vistos = set()
    chaves_existentes = set()
    
    # 3. Extrair todos os arquétipos
    for macro_cat, arch_name, arch_url in archetype_links:
        linhas_t1 = extrair_arquetipo(
            macro_cat, arch_name, arch_url, 
            decks_ja_vistos, chaves_existentes, 
            todos_decks_tabela2, dict_categorias_tabela3
        )
        todas_linhas_tabela1.extend(linhas_t1)
        
    # 4. Atribuir Card_ID para novas cartas descobertas nesta execução
    for card_name in sorted(dict_categorias_tabela3.keys()):
        if card_name not in dict_card_ids:
            dict_card_ids[card_name] = proximo_id
            proximo_id += 1
            
    # 5. Salvar Tabela 3 (Incremental: Card_ID, Card, Category)
    linhas_t3 = [
        {'Card_ID': dict_card_ids[card], 'Card': card, 'Category': cat}
        for card, cat in dict_categorias_tabela3.items()
    ]
    df_tabela3 = pd.DataFrame(linhas_t3).sort_values(by='Card_ID')
    
    df_tabela3 = aplicar_threat_type(df_tabela3, valor_padrao="None")
    
    df_tabela3.to_csv(arquivo_tabela3, index=False, encoding='utf-8-sig')
    print(f"\nTabela 3 atualizada! Total acumulado de cartas únicas: {len(df_tabela3)}")
    
    # 6. Salvar Tabela 1
    df_tabela1 = pd.DataFrame(todas_linhas_tabela1)
    df_tabela1.to_csv('tabela1_decks_pauper.csv', index=False, encoding='utf-8-sig')
    print(f"Tabela 1 gerada! Total de participações/decks únicos: {len(df_tabela1)}")
    
    # 7. Salvar Tabela 2 (Compartilhando Card_ID e Card com a Tabela 3)
    if todos_decks_tabela2:
        df_tabela2 = pd.DataFrame.from_dict(todos_decks_tabela2, orient='columns').fillna(0).astype(int)
        df_tabela2.index.name = 'Card'
        df_tabela2 = df_tabela2.reset_index()
        
        # Insere o Card_ID compartilhado com a Tabela 3 logo na primeira coluna
        df_tabela2.insert(0, 'Card_ID', df_tabela2['Card'].map(dict_card_ids))
        df_tabela2 = df_tabela2.sort_values(by='Card_ID')
        
        df_tabela2.to_csv('tabela2_cartas_por_jogador.csv', index=False, encoding='utf-8-sig')
        print(f"Tabela 2 gerada! Dimensões: {df_tabela2.shape[0]} cartas x {df_tabela2.shape[1] - 2} jogadores.")

if __name__ == '__main__':
    main()