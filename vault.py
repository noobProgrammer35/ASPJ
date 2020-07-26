import os
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient,EncryptionAlgorithm
from azure.identity import DefaultAzureCredential, ClientSecretCredential
import base64

# keyVaultName = os.environ["KEY_VAULT_NAME"]
# KVUri = "https://" + keyVaultName + ".vault.azure.net"
# _credential = ClientSecretCredential(
#     tenant_id="db539596-3662-417a-8a40-f760781d1cf8",
#     client_id="ee4319a3-b418-413d-a9e9-d3b23e2e17c5",
#     client_secret="33kU2I7F~a5TSDP-_Z9NZ1tR5DVlsgpK-W",
# )
# client = SecretClient(vault_url=KVUri, credential=_credential)
# print(client.get_secret('dbpw').value)
# key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
# key_client = KeyClient(vault_url=KVUri,credential=_credential)
# print(key_client.get_key('test').name)
# key = key_client.create_key('test',"RSA",size=2048,key_operations=key_ops)
# crypto_client = CryptographyClient(key_client.get_key('test'),credential=_credential)
# result = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep,b'FUCK U')
# print(result)
# print(result.algorithm)
# print(result.ciphertext)
# print(result.key_id)
class Vault:
    def __init__(self):
        self.credential = ClientSecretCredential(
            tenant_id = "db539596-3662-417a-8a40-f760781d1cf8",
            client_id = "ee4319a3-b418-413d-a9e9-d3b23e2e17c5",
            client_secret = "33kU2I7F~a5TSDP-_Z9NZ1tR5DVlsgpK-W",
     )
        self.secret_client = SecretClient(vault_url="https://{0}.vault.azure.net".format(os.getenv(("KEY_VAULT_NAME"))),credential=self.credential)
        self.key_client = KeyClient(vault_url="https://{0}.vault.azure.net".format(os.getenv(("KEY_VAULT_NAME"))),credential=self.credential)
        self.key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]

    def get_secret(self,key):
        return self.secret_client.get_secret(key).value

    def set_secret(self,key,value):
         self.secret_client.set_secret(key,value)

    def set_key(self,key_name,key_size,key_ops):
         self.key_client.create_key(key_name,"RSA",size=key_size,key_operations=key_ops)

    def encrypt(self,key_name,plaintext):
        key = self.key_client.get_key(key_name)
        crypto_client = CryptographyClient(key,credential=self.credential)
        text = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep,bytes(plaintext.encode()))
        return text.ciphertext

    def decrypt(self,ciphertext,key_name):
        key = self.key_client.get_key(key_name)
        crypto_client = CryptographyClient(key,credential=self.credential)
        text = crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep,ciphertext)
        return text.plaintext.decode()



# #
# vault = Vault()
# # print(vault.get_secret('dbuser'))
# ciphertext = vault.encrypt(key_name='test',plaintext = 'Henry')
# print(ciphertext)
# print(vault.decrypt(ciphertext,'test'))

