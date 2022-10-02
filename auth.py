from codecs import encode
import jwt
import base64



payload = {'school':'udacity'}
algo = 'HS256' #HMAC-SHA 256
secret = 'learning'


# Encode a JWT

encoded_jwt = jwt.encode(payload, secret, algorithm=algo)
print(encoded_jwt)

# Decode a JWT

decoded_jwt = jwt.decode(encoded_jwt, secret, algorithms=algo)
print(decoded_jwt)


#A = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoiY2VudHJhbCBwYXJrIn0.H7sytXDEHK1fOyOYkII5aFfzEZqGIro0Erw_84jZuGc"

#B = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXJrIjoiYmF0dGVyeSBwYXJrIn0.bQEjsBRGfhKKEFtGhh83sTsMSXgSstFA_P8g2qV5Sns"

# Decode with Simple Base64 Encoding
decoded_base64 = base64.b64decode(str(encoded_jwt).split(".")[1]+"==")
print(decoded_base64)