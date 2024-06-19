import os,sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re
import glob
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
import urllib3
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from flask import Flask, render_template, request
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
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
}

_template = '''
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Helvetica, sans-serif;
            background-color: #f5f5f5;
            color: #323232;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }

        h1 {
            font-family: 'Arial', sans-serif;
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }

        a {
            color: #000;
            text-decoration: none;
        }

        .text {
            font-size: 16px;
            color: #323232;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        .container {
            background-color: #e9e9e9;
            padding: 15px;
            margin: 20px 0;
            border: 1px solid #8a8a8a;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        .button {
            padding: 15px 50px;
            margin: 10px 0;
            display: inline-block;
            background-color: #4CAF50;
            border: none;
            border-radius: 5px;
            color: white;
            text-align: center;
            text-decoration: none;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .button:hover {
            background-color: #45a049;
        }

        .github-icon {
            position: relative;
            top: 5px;
            margin-right: 10px;
        }
    </style>
    <title>LinkFinder Output</title>
</head>

<body contenteditable="true">
    <h1>LinkFinder Output</h1>
    <div class="text">
        $$content$$
    </div>
    <a class="button" contenteditable="false" href="https://github.com/m4ll0k/SecretFinder/issues/new"
        rel="nofollow noopener noreferrer" target="_blank">
        <span class="github-icon">
            <svg height="24" viewBox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
                <path
                    d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"
                    fill="none" stroke="#fff" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path>
            </svg>
        </span>
        Report an issue
    </a>
</body>

</html>
'''

# All the required functions starting from here
def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help'%sys.argv[0])
    print('Error: %s'%msg)
    sys.exit(0)

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
        return (paths if len(paths)> 0 else parser_error('Input with wildcard does not match any files.'))

    # method 5 - local file
    path = "file://%s"% os.path.abspath(input)
    return [path if os.path.exists(input) else parser_error('file could not be found (maybe you forgot to add http/https).')]


def html_save(output, output_file):
    ''' Save HTML output to a file and open it in a browser '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull, os.O_RDWR)
    
    try:
        with open(output_file, "w", encoding="utf-8") as text_file:
            text_file.write(_template.replace('$$content$$', output))
        
        print(f'URL to access output: file://{os.path.abspath(output_file)}')
        file_url = f'file:///{os.path.abspath(output_file)}'

        if sys.platform.startswith('linux'):
            subprocess.call(['xdg-open', file_url])
        else:
            webbrowser.open(file_url)
    
    except Exception as err:
        print(f'Output can\'t be saved in {output_file} due to exception: {err}')
    
    finally:
        os.dup2(hide, 1)

def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name')+'\t->\t'+match.get('matched').encode('ascii','ignore').decode('utf-8'))

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
    
    # add cookies
    # if cookies:
    #     headers['Cookie'] = cookies

    headers.update(default_headers)
    
    # proxy
    # proxies = {}
    # if proxy:
    #     proxies.update({
    #         'http': proxy,
    #         'https': proxy,
    #     })
    
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

@app.route('/InputLink', methods=['POST'])
def InputLink():
        url = request.form['URL']
        # print(url)
            # Configuration variables
        url_link = url
        output_file = "output.html"
        regex_pattern = None
        use_burp = False
        # cookies = "NewCookie"
        ignore_str = ""
        only_str = ""
        headers = ""
        # proxy = ""
        
        if url[-1:] == "/":
            # /aa/ -> /aa
            url = url[:-1]

        mode = 1
        if output_file == "cli":
            mode = 0
        
        # add regex
        if regex_pattern:
            # validate regular exp
            try:
                r = re.search(regex_pattern, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10, 50))))
            except Exception as e:
                print('Your python regex isn\'t valid')
                sys.exit()

            _regex = {
                'custom_regex' : regex_pattern
            }

        # Assuming extract is always True in this context as --extract was an action store_true
        content = send_request(url)
        urls = extractjsurl(content, url)

        # convert input to URLs or JS files (assuming extract is not always True in some cases)
        if not urls:
            urls = parser_input(url)

        # convert URLs to js file
        output = ''
        for url in urls:
            print('[ + ] URL: ' + url)
            if not use_burp:
                file = send_request(url)
            else:
                file = url.get('js')
                url = url.get('url')

            matched = parser_file(file, mode)
            if output_file == 'cli':
                cli_output(matched)
            else:
                output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>' % (escape(url), escape(url))
                for match in matched:
                    _matched = match.get('matched')
                    _named = match.get('name')
                    header = '<div class="text">%s' % (_named.replace('_', ' '))
                    body = ''
                    # find same thing in multiple context
                    if match.get('multi_context'):
                        # remove duplicate
                        no_dup = []
                        for context in match.get('context'):
                            if context not in no_dup:
                                body += '</a><div class="container">%s</div></div>' % (context)
                                body = body.replace(
                                    context, '<span style="background-color:yellow">%s</span>' % context)
                                no_dup.append(context)
                    else:
                        body += '</a><div class="container">%s</div></div>' % (match.get('context')[0] if len(match.get('context')) > 1 else match.get('context'))
                        body = body.replace(
                            match.get('context')[0] if len(match.get('context')) > 0 else ''.join(match.get('context')),
                            '<span style="background-color:yellow">%s</span>' % (match.get('context') if len(match.get('context')) > 1 else match.get('context'))
                        )
                    output += header + body
        if output_file != 'cli':
            # html_save(output,output_file)
            return render_template('output.html', data=output)
        #     return render_template('output.html', data=Markup(url))
        # return 'Invalid request'
