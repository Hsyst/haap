from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps
import requests
import os

# Verifica se a biblioteca PyJWT está instalada corretamente
try:
    jwt.encode({'test': 'test'}, 'secret', algorithm='HS256')
except AttributeError:
    print("ERRO: Biblioteca JWT incorreta instalada.")
    print("Execute: pip uninstall jwt && pip install PyJWT")
    exit(1)

app = Flask(__name__)

# Configurações - altere conforme necessário
HAAP_SERVER = "http://localhost:3001"  # URL do servidor HAAP
CLIENT_SECRET = "seu_segredo_super_secreto"  # Segredo para assinar JWTs
PORT = 5000  # Porta para esta API

# Dados do usuário em memória (simulando banco de dados)
users_db = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token de autorização ausente"}), 401
        
        try:
            # Remove o 'Bearer ' do token
            token = token.split()[1]
            data = jwt.decode(token, CLIENT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/auth/callback', methods=['GET'])
def auth_callback():
    """Endpoint que recebe o callback do HAAP após autorização"""
    callback_code = request.args.get('callback_code')
    if not callback_code:
        return jsonify({"error": "Código de callback ausente"}), 400
    
    # Verifica o token com o servidor HAAP
    try:
        response = requests.get(
            f"{HAAP_SERVER}/api/external-verify",
            params={"token": callback_code},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": "Erro ao verificar token",
            "details": str(e)
        }), 500
    
    if not data.get('valid'):
        return jsonify({
            "error": "Token inválido ou expirado",
            "details": data
        }), 401
    
    user_data = data.get('user', {})
    user_id = user_data.get('id')
    
    if not user_id:
        return jsonify({
            "error": "Dados do usuário incompletos",
            "received_data": data
        }), 400
    
    # Armazena os dados do usuário (simulando banco de dados)
    users_db[user_id] = user_data
    
    # Gera um JWT para o usuário (assinado por nós)
    try:
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, CLIENT_SECRET, algorithm="HS256")
    except Exception as e:
        return jsonify({
            "error": "Erro ao gerar token",
            "details": str(e)
        }), 500
    
    return jsonify({
        "token": token,
        "user": user_data,
        "expires_in": "24h"
    })

@app.route('/api/protected', methods=['GET'])
@token_required
def protected():
    """Endpoint protegido que requer autenticação"""
    token = request.headers.get('Authorization').split()[1]
    try:
        data = jwt.decode(token, CLIENT_SECRET, algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": str(e)}), 401
    
    user_id = data.get('user_id')
    
    if user_id not in users_db:
        return jsonify({"error": "Usuário não encontrado"}), 404
    
    return jsonify({
        "message": "Acesso autorizado",
        "user": users_db[user_id]
    })

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Endpoint para verificar um token JWT"""
    if not request.is_json:
        return jsonify({"error": "Content-Type deve ser application/json"}), 400
    
    token = request.json.get('token')
    if not token:
        return jsonify({"error": "Token ausente"}), 400
    
    try:
        data = jwt.decode(token, CLIENT_SECRET, algorithms=["HS256"])
        user_id = data.get('user_id')
        
        if user_id not in users_db:
            return jsonify({"valid": False, "error": "Usuário não encontrado"})
        
        return jsonify({
            "valid": True,
            "user": users_db[user_id],
            "expires_at": data.get('exp')
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expirado"})
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Token inválido"})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})

if __name__ == '__main__':
    print(f"Servidor HAAP Client rodando em http://localhost:{PORT}")
    print(f"Configure o callback do HAAP para: http://localhost:{PORT}/auth/callback")
    app.run(port=PORT)
