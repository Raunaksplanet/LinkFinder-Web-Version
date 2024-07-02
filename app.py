import os,sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re, math, glob, argparse, jsbeautifier, webbrowser, subprocess, base64, requests, string, random, urllib3
from html import escape
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from flask import Flask, render_template, request, redirect, url_for
from requests_file import FileAdapter
from lxml import html
from markupsafe import Markup
from urllib.parse import urlparse

# regex
_regex = {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)"
}

def getContext(matches,content,name,rex='.+?'):
    ''' get context '''
    items = []
    matches2 =  []
    for  i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s'%(rex,m,rex),content,re.IGNORECASE)

        item = {
            'matched'          : m,
            'name'             : name,
            'context'          : context,
            'multi_context'    : True if len(context) > 1 else False
        }
        items.append(item)
    return items


def parser_file(content,mode=1,more_regex=None,no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";",";\r\n").replace(",",",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1],re.VERBOSE|re.I)
        if mode == 1:
            all_matches = [(m.group(0),m.start(0),m.end(0)) for m in re.finditer(r,content)]
            items = getContext(all_matches,content,regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched' : m.group(0),
                'context' : [],
                'name'    : regex[0],
                'multi_context' : False
            } for m in re.finditer(r,content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex,item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items


def parser_input(input):
    ''' Parser Input '''
    # method 1 - url
    schemes = ('http://','https://','ftp://','file://','ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input,'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    'js': base64.b64decode(item.find('response').text).decode('utf-8','replace'),
                    'url': item.find('url').text
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return paths if len(paths) > 0 else 'Input with wildcard does not match any files.'


    # method 5 - local file
    path = "file://%s"% os.path.abspath(input)
    return  os.path.exists(input) 

def urlParser(url):
    ''' urlParser '''
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc
    urlParser.this_path = parse.scheme + '://' + parse.netloc  + '/' + parse.path

def extractjsurl(content, base_url, ignore_str="", only_str=""):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []

    urlParser(base_url)
    
    for src_elem in soup.xpath('//script'):
        src = src_elem.xpath('@src')[0] if src_elem.xpath('@src') else None
        if src:
            if src.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http:' + src
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src
                if src not in all_src:
                    all_src.append(src)

    if ignore_str and all_src:
        temp = all_src[:]
        ignore = []
        for i in ignore_str.split(';'):
            ignore.extend([src for src in all_src if i in src])
        
        if ignore:
            temp = [src for src in temp if src not in ignore]
        
        return temp
    
    if only_str and all_src:
        temp = []
        for i in only_str.split(';'):
            temp.extend([src for src in all_src if i in src])
        
        return temp
    
    return all_src

def send_request(url):
    ''' Send Request '''
    # read local file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://', FileAdapter())
        return s.get(url).content.decode('utf-8', 'replace')
    
    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip'
    }
    
    if headers:
        for i in headers.split('\\n'):
            # replace space and split
            name, value = i.replace(' ', '').split(':')
            headers[name] = value
    
    headers.update(default_headers)
    
    try:
        resp = requests.get(
            url=url,
            verify=False,
            headers=headers,
            # proxies=proxies
        )
        return resp.content.decode('utf-8', 'replace')
    except Exception as err:
        print(err)
        sys.exit(0)



# Main app start from here
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():    
    file = request.files['js-file']
    file_lines = file.read().decode('utf-8').splitlines()
    return redirect(url_for('display_lines', lines=file_lines, page=1))

@app.route('/display_lines')
def display_lines():
    lines = request.args.getlist('lines')
    page = int(request.args.get('page', 1))
    lines_per_page = 1
    
    total_pages = math.ceil(len(lines) / lines_per_page)
    start = (page - 1) * lines_per_page
    end = start + lines_per_page

    output = ""
    mode = 1
    urls = lines  # Assuming lines is a list of URLs
    
    if not urls:
        # Handle case where no URLs are provided
        return "No URLs provided."

    for url in urls:
        file_content = send_request(url)  # Assuming send_request function exists
        matched_results = parser_file(file_content, mode)  # Assuming parser_file function exists
        
        output += f'<h1>File: <a href="{escape(url)}" target="_blank" rel="nofollow noopener noreferrer">{escape(url)}</a></h1>'
        
        for match in matched_results:
            _named = match.get('name').replace('_', ' ')
            header = f'<div class="text">{_named}'
            body = ''
            
            contexts = match.get('context', [])
            unique_contexts = list(dict.fromkeys(contexts)) if match.get('multi_context') else contexts[:1]
            
            for context in unique_contexts:
                highlighted_context = f'<span style="background-color:red">{context}</span>'
                body += f'<div class="container">{highlighted_context}</div>'
            
            output += header + body

     
    return render_template('output2.html', lines=lines[start:end], page=page, total_pages=total_pages, lines_param=lines)
   
# ------------------------------------------------------------------------------------------------------


@app.route('/InputLink', methods=['POST'])
def InputLink():
        url = request.form['URL']
        mode = 1
        total_pages = 1
        output_file = "output.html"
        headers = ""
        output = ""
        urls=""

        if not urls:
            content = send_request(url)
            urls = extractjsurl(content, url)
            urls = parser_input(url)

        # convert URLs to js file
        for url in urls:
            file = send_request(url)
            matched = parser_file(file, mode)
            output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>' % (escape(url), escape(url))
            for match in matched:
                _named = match.get('name').replace('_', ' ')
                header = f'<div class="text">{_named}'
                body = ''

                contexts = match.get('context', [])
                unique_contexts = list(dict.fromkeys(contexts)) if match.get('multi_context') else contexts[:1]
                
                for context in unique_contexts:
                    highlighted_context = f'<span style="background-color:red">{context}</span>'
                    body += f'</a><div class="container">{highlighted_context}</div></div>'
                
                output += header + body

        
        return render_template('output.html', data=output, total_pages=total_pages)

if __name__ == '__main__':
    app.run(debug=True)
