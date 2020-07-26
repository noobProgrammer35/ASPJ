import redis
from flask import current_app
from flask_session import Session


session = Session(current_app)
# # test = redis.Redis(host='redis-19402.c56.east-us.azure.cloud.redislabs.com',port=19402,db=0,password='PuCM6RZWRfmdXIGARO2Oei7lcLS3QfKD')
#  print(test)
# 'rediss://:password@hostname:port/0'
# test.delete('foo')




