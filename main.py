from flask import Flask, render_template, request, redirect, url_for, abort
import requests
import json

app = Flask(__name__)

VIRUSTOTAL_API_KEY = "7aad87516e044dbcd68662e3c2e34f1be7269e7b965bc47d13e14912df1547e5"

def get_malware_details(hash):
    try:
        url = f'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': hash}
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise HTTPError for bad status codes
        result = response.json()
        return result
    except requests.exceptions.RequestException as e:
        # Log or handle the error as needed
        print("Error fetching malware details:", e)
        abort(404)  # Redirect to 404 page if there's an error
    except json.JSONDecodeError as e:
        # Log or handle the JSON decoding error
        print("JSON decoding error:", e)
        abort(404)  # Redirect to 404 page if there's an error

def upload_file(file):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': VIRUSTOTAL_API_KEY}
        files = {'file': (file.filename, file.read())}
        response = requests.post(url, files=files, params=params)
        response.raise_for_status()  # Raise HTTPError for bad status codes
        json_response = response.json()
        resource = json_response['resource']

        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise HTTPError for bad status codes
        result = response.json()
        return result
    except requests.exceptions.RequestException as e:
        # Log or handle the error as needed
        print("Error uploading file:", e)
        abort(404)  # Redirect to 404 page if there's an error
    except json.JSONDecodeError as e:
        # Log or handle the JSON decoding error
        print("JSON decoding error:", e)
        abort(404)  # Redirect to 404 page if there's an error

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/malware_details', methods=['POST'])
def malware_details():
    if request.method == 'POST':
        hash_to_check = request.form['hash']
        file = request.files['file']
        result = None
        if file.filename:
            result = upload_file(file)
        elif hash_to_check:
            result = get_malware_details(hash_to_check)
        return render_template('result.html', result=result)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=False)
