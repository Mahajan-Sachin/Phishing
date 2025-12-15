import re
import tldextract
from urllib.parse import urlparse
import numpy as np
# Helper: split tokens safely
def safe_split(s):
    return re.split(r'\W+', s)

def extract_url_features(url):
    url = url.strip()
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full = url.lower()

    # Basic parts
    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    subdomain = ext.subdomain.lower()

    # Words for lexical features
    words_raw = safe_split(full)
    words_host = safe_split(hostname)
    words_path = safe_split(path)

    # Feature dictionary
    f = {}

    # === BASIC LENGTH FEATURES ===
    f['length_url'] = len(full)
    f['length_hostname'] = len(hostname)

    # === STRUCTURE / SYMBOL COUNTS ===
    f['ip'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}', hostname)))
    f['nb_dots'] = full.count('.')
    f['nb_hyphens'] = full.count('-')
    f['nb_at'] = full.count('@')
    f['nb_qm'] = full.count('?')
    f['nb_and'] = full.count('&')
    f['nb_or'] = full.count('|')
    f['nb_eq'] = full.count('=')
    f['nb_underscore'] = full.count('_')
    f['nb_tilde'] = full.count('~')
    f['nb_percent'] = full.count('%')
    f['nb_slash'] = full.count('/')
    f['nb_star'] = full.count('*')
    f['nb_colon'] = full.count(':')
    f['nb_comma'] = full.count(',')
    f['nb_semicolumn'] = full.count(';')
    f['nb_dollar'] = full.count('$')
    f['nb_space'] = full.count(' ')  # almost always 0

    f['nb_www'] = int('www' in hostname)
    f['nb_com'] = int('.com' in full)
    f['nb_dslash'] = full.count('//')

    # === URL TOKEN FEATURES ===
    f['http_in_path'] = int('http' in path)
    f['https_token'] = int(full.startswith('https'))
    digits_url = sum(c.isdigit() for c in full)
    digits_host = sum(c.isdigit() for c in hostname)

    f['ratio_digits_url'] = digits_url / max(1, len(full))
    f['ratio_digits_host'] = digits_host / max(1, len(hostname))

    # === PUNYCODE & PORT ===
    f['punycode'] = int('xn--' in hostname)
    f['port'] = 0
    try:
        f['port'] = parsed.port if parsed.port else 0
    except:
        f['port'] = 0

    # === TLD, SUBDOMAIN, PREFIX/SUFFIX ===
    f['tld_in_path'] = int(suffix in path)
    f['tld_in_subdomain'] = int(suffix in subdomain)
    f['abnormal_subdomain'] = int(len(subdomain.split('.')) > 3)
    f['nb_subdomains'] = len([x for x in subdomain.split('.') if x])

    # prefix-suffix like “secure-paypal”
    f['prefix_suffix'] = int('-' in domain)

    # random domain (simple heuristic: long + digits)
    f['random_domain'] = int(bool(re.search(r'[0-9]', domain)) and len(domain) >= 10)

    # === SHORTENERS ===
    shortening_list = ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly']
    f['shortening_service'] = int(any(s in full for s in shortening_list))

    # === PATH EXTENSION ===
    f['path_extension'] = int(bool(re.search(r'\.[a-zA-Z0-9]{1,4}$', path)))

    # === REDIRECTIONS ===
    f['nb_redirection'] = full.count('//') - 1
    f['nb_external_redirection'] = int('//' in path)

    # === LEXICAL FEATURES ===
    # Raw words
    f['length_words_raw'] = np.mean([len(w) for w in words_raw]) if words_raw else 0
    f['char_repeat'] = int(bool(re.search(r'(.)\1{2,}', full)))

    # shortest
    f['shortest_words_raw'] = min([len(w) for w in words_raw]) if words_raw else 0
    f['shortest_word_host'] = min([len(w) for w in words_host]) if words_host else 0
    f['shortest_word_path'] = min([len(w) for w in words_path]) if words_path else 0

    # longest
    f['longest_words_raw'] = max([len(w) for w in words_raw]) if words_raw else 0
    f['longest_word_host'] = max([len(w) for w in words_host]) if words_host else 0
    f['longest_word_path'] = max([len(w) for w in words_path]) if words_path else 0

    # averages
    f['avg_words_raw'] = f['length_words_raw']
    f['avg_word_host'] = np.mean([len(w) for w in words_host]) if words_host else 0
    f['avg_word_path'] = np.mean([len(w) for w in words_path]) if words_path else 0

    # === PHISHY PATTERN FEATURES ===
    suspicious_keywords = ['secure','account','login','update','verify','bank','signin','confirm','alert']
    f['phish_hints'] = sum(1 for k in suspicious_keywords if k in full)

    f['domain_in_brand'] = int(domain in full)
    f['brand_in_subdomain'] = int(any(k in subdomain for k in suspicious_keywords))
    f['brand_in_path'] = int(any(k in path for k in suspicious_keywords))

    # === SUSPICIOUS TLD ===
    bad_tlds = ['ru','cn','tk','ml','ga','gq']
    f['suspecious_tld'] = int(suffix in bad_tlds)

    # === STATISTICAL REPORT (simple heuristic) ===
    # Usually this was from PhishTank; we simulate lexical score
    f['statistical_report'] = int(f['phish_hints'] > 1 or f['nb_dots'] > 4)

    return f
