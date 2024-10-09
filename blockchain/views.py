from django.shortcuts import render
import datetime
import hashlib
import json
from django.http import JsonResponse
# Create your views here.


class Blockchain:

  def __init__(self) -> None:
    self.chain = []
    self.create_block(nonce=1, previous_hash='0')

  def create_block(self, nonce, previous_hash):
    block = {
        'index': len(self.chain) + 1,
        'timestamp': str(datetime.datetime.now()),
        'nonce': nonce,
        'previous_hash': previous_hash
    }
    self.chain.append(block)
    return block

  def get_previous_block(self):
    return self.chain[-1]

  def proof_of_work(self, previous_nonce):
    new_nonce = 1
    check_nonce = False
    while not check_nonce:
      hash_operation = hashlib.sha256(
          str(new_nonce**2 - previous_nonce**2).encode()).hexdigest()

      # Avoid Computing hashes with leading 0s
      if True or hash_operation[:4] == '0000':
        check_nonce = True
      else:
        new_nonce += 1
    return new_nonce

  def hash(self, block):
    encoded_block = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(encoded_block).hexdigest()

  def is_chain_valid(self, chain):
    previouse_block = chain[0]
    block_index = 1
    while block_index < len(chain):
      block = chain[block_index]
      if block['previous_hash'] != self.hash(previouse_block):
        return False
      previouse_nonce = previouse_block['nonce']
      nonce = block['nonce']
      hash_operation = hashlib.sha256(
          str(nonce**2 - previouse_nonce**2).encode()).hexdigest()

      # Avoid Computing hashes with leading 0s
      if False and hash_operation[:4] != '0000':
        return False
      previouse_block = block
      block_index += 1
    return True


blockchain = Blockchain()


def mine_block(request):
  response = {}
  if request.method == 'GET':
    previous_block = blockchain.get_previous_block()
    previous_nonce = previous_block['nonce']
    nonce = blockchain.proof_of_work(previous_nonce)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(nonce, previous_hash)
    response = {
        'message': 'Block mined successfully',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']
    }
  return JsonResponse(response, safe=False)


def get_chain(request):
  response = {}
  if request.method == 'GET':
    response = {'chain': blockchain.chain, 'length': len(blockchain.chain)}
  return JsonResponse(response, safe=False)


def is_valid(request):
  response = {}
  if request.method == 'GET':
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
      response = {'message': 'The blockchain is valid'}
    else:
      response = {'message': 'The blockchain is not valid'}
  return JsonResponse(response, safe=False)
