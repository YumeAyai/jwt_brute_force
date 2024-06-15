import jwt
from concurrent.futures import ThreadPoolExecutor

def decode_jwt(token, key):
    try:
        decoded = jwt.decode(token, key, algorithms=['HS256'])
        return decoded
    except jwt.ExpiredSignatureError:
        return "Token 已过期"
    except jwt.InvalidTokenError:
        return None

def read_keys_from_file(filename):
    with open(filename, "r") as file:
        keys = [line.strip() for line in file.readlines()]
    return keys

def brute_force_jwt(jwt_token, keys):
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(decode_jwt, jwt_token, key): key for key in keys}
        for future in futures:
            key = futures[future]
            decoded_token = future.result()
            if decoded_token is not None:
                print("使用密钥 {} 解密成功:".format(key))
                print(decoded_token)
                return decoded_token
        print("无法解密，尝试更多的密钥。")

if __name__ == "__main__":
    # jwt_token = input("请输入要解密的 JWT Token: ")
    jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IjEiLCJwYXNzd29yZCI6IjEiLCJyb2xlIjoiZ3Vlc3QifQ.t4x7IB9QOV9sUyWghtZNfpJdSYuB1vd6en-7mF91J9I"
    # key_file = input("请输入包含可能密钥的文件路径: ")
    key_file = "key.txt"
    
    possible_keys = read_keys_from_file(key_file)
    brute_force_jwt(jwt_token, possible_keys)
