from flask import Flask, request, render_template
import requests
from bs4 import  BeautifulSoup
import aiohttp
import asyncio
from urllib.parse import urljoin
from const import *

app = Flask(__name__)

def extract_url(base_url):
    try:
        response = requests.get(base_url)
        soup = BeautifulSoup(response.content, 'html.parser')
        urls = { a['href']  for a in soup.find_all('a', href = True)}
        full_url = {urljoin(base_url, url) for url in urls}
        full_url.add(base_url)

        return full_url
    except Exception as e:
        return []

async def get_id(session, id):
    try:
        headers = {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'accept':'application/json',
                }
        url = f'https://www.virustotal.com/api/v3/analyses/{id}'

        async with session.get(url, headers = headers) as response:
            data = await response.json()
            return data['data']['attributes']['stats']

    except Exception as e:
        return {'error': str(e)}

async def scan_url(session, url):
    try:
        data = {'url': url}
        headers = {
                'x-apikey': VIRUSTOTAL_API_KEY,
                'accept':'application/json',
                'content-type': 'application/x-www-form-urlencoded'
                }
        async with session.post('https://www.virustotal.com/api/v3/urls', headers = headers, data = data) as response:
            result = await response.json()
            id = result['data']['id']
            return await get_id(session, id)

    except Exception as e:
        return {'error': str(e)}

@app.route('/', methods = ['GET', 'POST'])
def index():
    if request.method == 'POST':
        page_url = request.form.get('page_url')
        urls = extract_url(page_url)

        async def scan_all_urls():
            async with aiohttp.ClientSession() as session:
                task = [scan_url(session, url) for url in urls]
                result = await asyncio.gather(*task)
                return dict(zip(urls, result))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        scan_result = loop.run_until_complete(scan_all_urls())
        loop.close()

        return render_template('results.html', scan_result = scan_result)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host = "0.0.0.0", port = 5000)
