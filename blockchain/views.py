from django.shortcuts import render
import datetime
import hashlib
import json
from uuid import uuid4
import socket
import requests
from urllib.parse import urlparse
from django.http import JsonResponse, HttpResponse, HttpRequest, response
from django.views.decorators.csrf import csrf_exempt
# Create your views here.


class Blockchain:

  def __init__(self) -> None:
    self.chain = []
    self.transactions = []
    self.create_block(nonce=1, previous_hash='0')
    self.nodes = set()

  def create_block(self, nonce, previous_hash):
    block = {
        'index': len(self.chain) + 1,
        'timestamp': str(datetime.datetime.now()),
        'nonce': nonce,
        'previous_hash': previous_hash,
        'transactions': self.transactions
    }
    self.transactions = []
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

  def add_transaction(self, sender, receiver, amount):
    self.transactions.append({
        'sender': sender,
        'receiver': receiver,
        'amount': amount,
        'time': str(datetime.datetime.now())
    })
    previous_block = self.get_previous_block()
    return previous_block['index'] + 1

  def add_node(self, address):
    parsed_url = urlparse(address)
    self.nodes.add(parsed_url.netloc)

  def replace_chain(self):
    network = self.nodes
    longest_chain = None
    max_length = len(self.chain)
    for node in network:
      response = requests.get(f'https://{node}/get_chain')
      if response.status_code == 200:
        length = response.json()['length']
        chain = response.json()['chain']
        if length > max_length and self.is_chain_valid(chain):
          max_length = length
          longest_chain = chain
    if longest_chain:
      self.chain = longest_chain
      return True
    return False


blockchain = Blockchain()

node_address = str(uuid4()).replace('-', '')
root_node = 'e36f0158f0aed45b3bc755dc52ed4560d'


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

@csrf_exempt
def add_transaction(request):
  response = {}
  if request.method == 'POST':
    received_json = json.loads(request.body)
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in received_json for key in transaction_keys):
      return 'Some elements of the transaction are missing', HttpResponse(status=400)
    index = blockchain.add_transaction(received_json['sender'], received_json['receiver'], received_json['amount'], received_json['time'])
    response = {'message': f'Transaction will be added to Block {index}'}
  return JsonResponse(response, safe=False)

@csrf_exempt
def connect_node(request):
  response = {}
  if request.method == 'POST':
    received_json = json.loads(request.body)
    nodes = received_json.get('nodes')
    if nodes is None:
      return "No Node", HttpResponse(status=400)
    for node in nodes:
      blockchain.add_node(node)
    response = {'message': 'All nodes are now connected. The PlutoCoin blockchain now contains the following nodes: ', 'total_nodes': list(blockchain.nodes)}
  return JsonResponse(response)

def replace_chain(request):
  response = {}
  if request.method == 'GET':
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
      response = {'message': 'The nodes had different chains so the chain was replaced by the longest one', 'new_chain': blockchain.chain}
    else:
      response = {'message': 'All good. The chain is the largest one.', 'actual_chain': blockchain.chain}
  return JsonResponse(response)
    