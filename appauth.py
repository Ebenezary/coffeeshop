from flask import Flask, app, request, abort
from functools import wraps
import json
import sys
from jose import jwt
from urllib.request import urlopen



AUTH0_DOMAIN = 'alaxudacity.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'image'



'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code











## Auth Header
def verify_decode_jwt(token):
    # GET THE PUBLIC KEY FROM AUTH0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    
    # GET THE DATA IN THE HEADER
    unverified_header = jwt.get_unverified_header(token)
    
    # CHOOSE OUR KEY
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            # USE THE KEY TO VALIDATE THE JWT
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)


# PASTE YOUR OWN TOKEN HERE
# MAKE SURE THIS IS A VALID AUTH0 TOKEN FROM THE LOGIN FLOW
#token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkpvM3FIX2pVQk9ZYTh1RmxfRjlGaSJ9.eyJpc3MiOiJodHRwczovL2FsYXh1ZGFjaXR5LnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHw2MzJmMDk5ZTY3ZWM3ZTM5NmEwMzI3NjYiLCJhdWQiOiJpbWFnZSIsImlhdCI6MTY2NDAyNzAzOSwiZXhwIjoxNjY0MDM0MjM5LCJhenAiOiJUTE9kQkRCWU9GS0FXbTVtYzRuZUxOcGlmUHRLNXJoeSIsInNjb3BlIjoiIn0.aJ5VwPmB7prd75yEls6T0dYaZvbW2EqOjLO-FCg0Vs-KIwsw042OZYFObLL2hYtrYrtNeHfxwhtz77D0HLv50HWqXL4IDvecVI1ZDFYv6mdPX5u-9dVa7bDcS1F0aBYzu1PWkQLKfULbPVShXDlX8D_I_US0LCHYKf5Z3rtK_WoTi3TOFwuNnPmCgPppfmhA551CQEutIHj4inp7edk6zOEzAQXFp5Xo-1q8y9rdjaXFnp15BHjOHiYhSrocT3973OWUzTBLGRLxPRHoIxQ_fX2LAxCR499DAgEk-zSC1rSi7f07VjEWgHxF7pyYeHq3dpJGNt9b_-Vdl9F8669MLg"














def get_token_auth_header():

    if 'Authorization' not in request.headers:
        abort(401)

    auth_header = request.headers['Authorization']
    # get the token
    header_parts = auth_header.split(' ')

    if len(header_parts) != 2:
        abort(401)

    elif header_parts[0].lower() != 'bearer':
        abort(401)

    return header_parts[1] 



def check_permissions(permission, payload):
    if 'permissions' not in payload:
                        raise AuthError({
                            'code': 'invalid_claims',
                            'description': 'Permissions not included in JWT.'
                        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)
    return True


def requires_auth(permission = ''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            jwt = get_token_auth_header()

            try:
               payload = verify_decode_jwt(jwt)
        
            except:
               abort(401)


            check_permissions(permission, payload)   
            return f(payload, *args, **kwargs)
        return wrapper  
    return requires_auth_decorator        

app = Flask(__name__)

#@app.route('/headers')
#@requires_auth('get:image')
#def headers(jwt):
 #   print(jwt)
  #  return "not implemented"

@app.route('/images')
#@requires_auth('get:imges')
def image():
    #print(jwt)
    return "not implemented" 