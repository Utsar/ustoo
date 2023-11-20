from flask import Flask, redirect, url_for, session, request
from google_auth_oauthlib.flow import Flow
from dotenv import load_dotenv
import os
import msal
import uuid

# Load environment variables
load_dotenv()

# Set environment variable for development only
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ONLY for development

# Retrieve tenant ID from environment variables
ms_tenant_id = os.getenv('AZURE_DIRECTORY_TENANT_ID')

# Add your Microsoft Azure configuration here
ms_client_id = os.getenv('MS_AZURE_CLIENT_ID')
ms_secret = os.getenv('AZURE_CLIENT_SECRET')
ms_authority = f'https://login.microsoftonline.com/{ms_tenant_id}'
ms_scopes = ['Calendars.Read']
ms_redirect_uri = 'http://localhost:5000/callback/microsoft'

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  

@app.route('/')
def index():
    # Home page with links to Google and Microsoft auth
    return '''
        <a href="/login/google">Authorize Google</a><br>
        <a href="/login/microsoft">Authorize Microsoft</a>
    '''

@app.route('/login/google')
def login_google():
    flow = Flow.from_client_secrets_file(
        client_secrets_file="google_client.json",
        scopes=['https://www.googleapis.com/auth/calendar.events.readonly'],
        redirect_uri='http://localhost:5000/callback/google'
    )
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback/google')
def callback_google():
    flow = Flow.from_client_secrets_file(
        client_secrets_file="google_client.json",
        scopes=['https://www.googleapis.com/auth/calendar.events.readonly'],
        redirect_uri='http://localhost:5000/callback/google',
        state=session['state']
    )
    flow.fetch_token(authorization_response=request.url)
    return redirect(url_for('index'))

    # Here, you should store the credentials securely for future use
    # For now, we'll just redirect to the home page


#MICROSOFT
@app.route('/login/microsoft')
def login_microsoft():
    # Create a Microsoft Authentication Context
    msal_app = msal.ConfidentialClientApplication(
        ms_client_id, authority=ms_authority, client_credential=ms_secret
    )
    auth_url = msal_app.get_authorization_request_url(
        ms_scopes, state=str(uuid.uuid4()), redirect_uri=ms_redirect_uri
    )
    return redirect(auth_url)

@app.route('/callback/microsoft')
def callback_microsoft():
    # Extract the code from the response
    code = request.args.get('code')
    if code:
        msal_app = msal.ConfidentialClientApplication(
            ms_client_id, authority=ms_authority, client_credential=ms_secret
        )
        result = msal_app.acquire_token_by_authorization_code(
            code, scopes=ms_scopes, redirect_uri=ms_redirect_uri
        )
        if "access_token" in result:
            # Use the result['access_token'] to make Microsoft Graph API calls
            # You can store this token in the session or a database
            session['ms_token'] = result['access_token']
            # Redirect or handle the response as needed
            return redirect(url_for('index'))
        else:
            # Handle the error
            return f"Error acquiring token: {result.get('error_description')}"
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
