import requests
import json
from base64 import b64encode

def test_return_status_code():
    response = requests.get("http://localhost:5000/user")
    assert response.status_code == 200

def test_can_post_new_user():
    payload = {
            'password': 'pineapple',
            'name': 'stevie b'
            }
    response = requests.post("http://localhost:5000/user", data=json.dumps(payload))
    assert response.status_code == 200
    assert json.loads(response.content) == {'message': 'New user created'}

def test_can_get_all_users():
    response = requests.get("http://localhost:5000/user")
    assert response.status_code == 200
    assert len(response.content) > 0

def test_can_return_one_user():
    response = requests.get("http://localhost:5000/user/1")
    assert response.status_code == 200

def test_can_delete_user():
    public_id = 'f87f29c8-9843-4e34-9c68-1bd6449c7c5e'
    response = requests.delete(f"http://localhost:5000/user/{public_id}")
    assert response.status_code == 200

# def test_can_promote_one_user():
#     public_id = 'f87f29c8-9843-4e34-9c68-1bd6449c7c5e'
#     response = requests.put(f"http://localhost:5000/user/{public_id}")
#     assert response.status_code == 200
#     assert json.loads(response.content) == {'message': 'User promoted'}

def test_can_login():
    username = 'stevie b'
    password = 'pineapple'
    credentials = b64encode(b"stevie b:pineapple").decode()
    res = requests.get("http://localhost:5000/login", headers={"Authorization": f"Basic {credentials}"})
    assert res.status_code == 200
    assert 'token' in str(res.content)

