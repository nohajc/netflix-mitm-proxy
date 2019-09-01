from mitmproxy import ctx
from mitmproxy import http
import json
from base64 import b64encode, urlsafe_b64encode
from base64 import b64decode, urlsafe_b64decode

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import unpad

import logging
import random
import gzip

import math
import re

BYTE_SIZE = 8
BYTE_RANGE = 256
UNCOMPRESS_DICTIONARY = [[ui] for ui in range(0, BYTE_RANGE)]

def lzw_decompress(data):
	dictionary = UNCOMPRESS_DICTIONARY[:]

	codeIndex = 0
	codeOffset = 0
	bits = BYTE_SIZE
	uncompressed = [0 for i in range(0, math.ceil(len(data) * 1.5))]
	index = 0
	nextIndex = 0
	prevValue = []

	while codeIndex < len(data):
		bitsAvailable = (len(data) - codeIndex) * BYTE_SIZE - codeOffset
		if bitsAvailable < bits:
			break

		code = 0
		bitsDecoded = 0
		while bitsDecoded < bits:
			bitlen = min(bits - bitsDecoded, BYTE_SIZE - codeOffset)
			msbits = data[codeIndex]

			msbits <<= codeOffset
			msbits &= 0xff
			msbits >>= BYTE_SIZE - bitlen

			bitsDecoded += bitlen
			codeOffset += bitlen
			if codeOffset == BYTE_SIZE:
				codeOffset = 0
				codeIndex += 1

			code |= (msbits & 0xff) << (bits - bitsDecoded)

		value = None if code >= len(dictionary) else dictionary[code]
		if len(prevValue) == 0:
			bits += 1
		else:
			if not value:
				prevValue.append(prevValue[0])
			else:
				prevValue.append(value[0])

			dictionary.append(prevValue)
			prevValue = []

			if len(dictionary) == (1 << bits):
				bits += 1

			if not value:
				value = dictionary[code]

		nextIndex = index + len(value)

		if nextIndex >= len(uncompressed):
			increase = math.ceil(nextIndex * 1.5) - len(uncompressed)
			uncompressed.extend([0] * increase)

		uncompressed[index:index] = value
		index = nextIndex

		prevValue = prevValue + value

	return bytes(uncompressed[0:index])


def b64urlencode(string):
    """
    Removes any `=` used as padding from the encoded string.
    """
    encoded = urlsafe_b64encode(string)
    return encoded.rstrip(b"=")

def b64urldecode(string):
    """
    Adds back in the required padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return urlsafe_b64decode(string)


ClientPublicKey = None
ProxyRSAKey = None
MSLAESKey = None
Mechanism = None

random.seed(0)

def pseudoRandomBytes(n):
	return bytes(random.getrandbits(8) for _ in range(n))

ProxySignKey = RSA.generate(2048, pseudoRandomBytes)

ServerSignPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlibeiUhffUDs6QqZiB+jXH/MNgITf7OOcMzuSv4G3JysWkc0aPbT3vkCVaxdjNtw50zo2Si8I24z3/ggS3wZaF//lJ/jgA70siIL6J8kBt8zy3x+tup4Dc0QZH0k1oxzQxM90FB5x+UP0hORqQEUYZCGZ9RbZ/WNV70TAmFkjmckutWN9DtR6WUdAQWr0HxsxI9R05nz5qU2530AfQ95h+WGZqnRoG0W6xO1X05scyscNQg0PNCy3nfKBG+E6uIl5JB4dpc9cgSNgkfAIeuPURhpD0jHkJ/+4ytpdsXAGmwYmoJcCSE1TJyYYoExuoaE8gLFeM01xXK5VINU7/eWjQIDAQAB"
ServerSignPubKey2 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm84o+RfF7KdJgbE6lggYAdUxOArfgCsGCq33+kwAK/Jmf3VnNo1NOGlRpLQUFAqYRqG29u4wl8fH0YCn0v8JNjrxPWP83Hf5Xdnh7dHHwHSMc0LxA2MyYlGzn3jOF5dG/3EUmUKPEjK/SKnxeKfNRKBWnm0K1rzCmMUpiZz1pxgEB/cIJow6FrDAt2Djt4L1u6sJ/FOy/zA1Hf4mZhytgabDfapxAzsks+HF9rMr3wXW5lSP6y2lM+gjjX/bjqMLJQ6iqDi6++7ScBh0oNHmgUxsSFE3aBRBaCL1kz0HOYJe26UqJqMLQ71SwvjgM+KnxZvKa1ZHzQ+7vFTwE7+yxwIDAQAB"

logging.basicConfig(filename='proxy.log', filemode='w', level=logging.INFO, format='%(message)s')


def appendChunk(parsedReqChunks, data):
	parsedChunk = None
	try:
		parsedChunk = json.loads(data)
		parsedReqChunks.append(parsedChunk)
	except json.JSONDecodeError as e:
		parsedChunk = json.loads(data[0:e.pos])
		parsedReqChunks.append(parsedChunk)
		appendChunk(parsedReqChunks, data[e.pos:])

def initSession():
	global MSLAESKey
	try:
		f = open("session.json", "r")
		session = json.loads(f.read())
		keyEncoded = session["AESKey"]
		MSLAESKey = b64urldecode(keyEncoded)
		logging.info("Loaded AESKey: " + keyEncoded)
		f.close()
	except json.JSONDecodeError:
		MSLAESKey = ""
		logging.info("Could not parse session.json")
	except IOError:
		MSLAESKey = ""
		logging.info("Could not open session.json")

def updateSession():
	global MSLAESKey
	try:
		f = open("session.json", "w")
		session = {
			"AESKey": b64urlencode(MSLAESKey).decode()
		}
		f.write(json.dumps(session))
		f.close()

	except IOError:
		pass

def isMSLAPI(url):
	return "msl_v1/cadmium" in url or "msl/cadmium" in url

def request(flow: http.HTTPFlow):
	global MSLAESKey
	if MSLAESKey == None:
		initSession()

	if isMSLAPI(flow.request.pretty_url):
		logging.info("Netflix msl request: " + flow.request.pretty_url)
		parsedRequest = None
		parsedReqChunks = []
		headerEndOffset = -1

		try:
			parsedRequest = json.loads(flow.request.content)
		except json.JSONDecodeError as e:
			headerEndOffset = e.pos
			parsedRequest = json.loads(flow.request.content[0:e.pos])
			appendChunk(parsedReqChunks, flow.request.content[e.pos:])

		#logging.info(flow.request.content.decode())
		if not "headerdata" in parsedRequest.keys():
			return

		headerData = b64decode(parsedRequest["headerdata"])
		#logging.info(headerData.decode())

		parsedHeaderData = json.loads(headerData)
		if "keyrequestdata" in parsedHeaderData.keys():
			#logging.info("ProxySignKey: " + b64encode(ProxySignKey.publickey().exportKey("DER")).decode())

			#logging.info(flow.request.content.decode())
			pubKeyStr = parsedHeaderData["keyrequestdata"][0]["keydata"]["publickey"]
			logging.info("Client pubkey: " + pubKeyStr)

			global Mechanism
			global ClientPublicKey
			global ProxyRSAKey

			Mechanism = parsedHeaderData["keyrequestdata"][0]["keydata"]["mechanism"]

			ClientPublicKey = RSA.import_key(b64decode(pubKeyStr))

			ProxyRSAKey = RSA.generate(2048)
			proxyPubKeyStr = b64encode(ProxyRSAKey.publickey().exportKey("DER")).decode()
			logging.info("To be replaced with: " + proxyPubKeyStr)

			parsedHeaderData["keyrequestdata"][0]["keydata"]["publickey"] = proxyPubKeyStr
			parsedRequest["headerdata"] = b64encode(json.dumps(parsedHeaderData).encode()).decode()

			contentRest = b""
			if headerEndOffset != -1:
				contentRest = flow.request.content[headerEndOffset:]
			flow.request.content = json.dumps(parsedRequest).encode() + contentRest

			#logging.info(flow.request.content.decode())

		elif "ciphertext" in parsedHeaderData.keys() and MSLAESKey != None:
			iv = b64decode(parsedHeaderData["iv"])
			cipher = AES.new(MSLAESKey, AES.MODE_CBC, iv)

			cipherText = b64decode(parsedHeaderData["ciphertext"])
			try:
				plainText = unpad(cipher.decrypt(cipherText), 16)
				logging.info(plainText.decode())
			except ValueError:
				logging.error("Error: incorrect AES key")

		#logging.info("Number of chunks: " + str(len(parsedReqChunks)))
		for chunk in parsedReqChunks:
			if MSLAESKey == None:
				continue

			payload = json.loads(b64decode(chunk["payload"]))
			iv = b64decode(payload["iv"])

			cipher = AES.new(MSLAESKey, AES.MODE_CBC, iv)

			cipherText = b64decode(payload["ciphertext"])
			try:
				plainText = unpad(cipher.decrypt(cipherText), 16)
			except ValueError:
				logging.error("Error: incorrect AES key")
				continue

			plainJSON = None

			try:
				plainJSON = json.loads(plainText)
			except json.JSONDecodeError as e:
				plainJSON = json.loads(plainText[0:e.pos])

			#logging.info(plainText.decode())
			decoded = b64decode(plainJSON["data"])
			if "compressionalgo" in plainJSON.keys():
				if plainJSON["compressionalgo"] == "GZIP":
					decoded = gzip.decompress(decoded)
				elif plainJSON["compressionalgo"] == "LZW":
					decoded = lzw_decompress(decoded)

			logging.info(decoded.decode())


def response(flow: http.HTTPFlow):
	if isMSLAPI(flow.request.pretty_url):
		logging.info("Netflix msl response: " + flow.request.pretty_url)
		parsedResponse = None
		parsedRespChunks = []
		headerEndOffset = -1

		try:
			parsedResponse = json.loads(flow.response.content)
		except json.JSONDecodeError as e:
			headerEndOffset = e.pos
			parsedResponse = json.loads(flow.response.content[0:e.pos])
			appendChunk(parsedRespChunks, flow.response.content[e.pos:])

		#logging.info(flow.response.content.decode())
		if not "headerdata" in parsedResponse.keys():
			return

		headerData = b64decode(parsedResponse["headerdata"])
		#logging.info(headerData.decode())

		parsedHeaderData = json.loads(headerData)
		if "keyresponsedata" in parsedHeaderData.keys():
			hmacKeyEncStr = parsedHeaderData["keyresponsedata"]["keydata"]["hmackey"]
			encKeyEncStr = parsedHeaderData["keyresponsedata"]["keydata"]["encryptionkey"]

			proxyCipher = PKCS1_OAEP.new(ProxyRSAKey)
			clientCipher = PKCS1_OAEP.new(ClientPublicKey)

			global MSLAESKey

			if Mechanism == "JWK_RSA":
				hmacKeyEnv = proxyCipher.decrypt(b64decode(hmacKeyEncStr))
				encKeyEnv = proxyCipher.decrypt(b64decode(encKeyEncStr))

				hmacKeyEncStr = b64encode(clientCipher.encrypt(hmacKeyEnv)).decode()
				encKeyEncStr = b64encode(clientCipher.encrypt(encKeyEnv)).decode()

				MSLAESKey = b64urldecode(json.loads(encKeyEnv)["k"])
				logging.info("MSL AES key: " + json.loads(encKeyEnv)["k"])
				updateSession()

			elif Mechanism == "JWEJS_RSA":
				hmacKeyJWEJS = json.loads(b64decode(hmacKeyEncStr))
				encKeyJWEJS = json.loads(b64decode(encKeyEncStr))

				logging.info("encryptionkey before: " + b64decode(encKeyEncStr).decode())
				logging.info("hmackey before: " + b64decode(hmacKeyEncStr).decode())

				encKey = proxyCipher.decrypt(b64urldecode(encKeyJWEJS["recipients"][0]["encrypted_key"]))
				gcmCipher = AES.new(encKey, AES.MODE_GCM, b64urldecode(encKeyJWEJS["initialization_vector"]))
				encKeyPlain = gcmCipher.decrypt(b64urldecode(encKeyJWEJS["ciphertext"])).decode()

				#logging.info("JWEJS message: " + encKeyPlain)

				MSLAESKey = b64urldecode(json.loads(encKeyPlain)["k"])
				logging.info("MSL AES key: " + json.loads(encKeyPlain)["k"])
				updateSession()

				encKeyJWEJS["recipients"][0]["encrypted_key"] = b64urlencode(clientCipher.encrypt(encKey)).decode()

				gcmCipher = AES.new(encKey, AES.MODE_GCM, b64urldecode(encKeyJWEJS["initialization_vector"]))
				aad = encKeyJWEJS["recipients"][0]["header"] + "." + encKeyJWEJS["recipients"][0]["encrypted_key"] + "." + encKeyJWEJS["initialization_vector"]
				gcmCipher.update(aad.encode())
				cip, tag = gcmCipher.encrypt_and_digest(encKeyPlain.encode())
				#logging.info("expected ciphertext: " + b64urlencode(cip).decode())
				#logging.info("expected integrity_value: " + b64urlencode(tag).decode())

				encKeyJWEJS["recipients"][0]["integrity_value"] = b64urlencode(tag).decode()

				encKeyJWEJS_str = json.dumps(encKeyJWEJS)
				encKeyJWEJS_str = re.sub('[\s+]', '', encKeyJWEJS_str)
				encKeyEncStr = b64encode(encKeyJWEJS_str.encode()).decode()

				hmacKey = proxyCipher.decrypt(b64urldecode(hmacKeyJWEJS["recipients"][0]["encrypted_key"]))
				gcmCipher = AES.new(hmacKey, AES.MODE_GCM, b64urldecode(hmacKeyJWEJS["initialization_vector"]))
				hmacKeyPlain = gcmCipher.decrypt(b64urldecode(hmacKeyJWEJS["ciphertext"])).decode()

				hmacKeyJWEJS["recipients"][0]["encrypted_key"] = b64urlencode(clientCipher.encrypt(hmacKey)).decode()

				gcmCipher = AES.new(hmacKey, AES.MODE_GCM, b64urldecode(hmacKeyJWEJS["initialization_vector"]))
				aad = hmacKeyJWEJS["recipients"][0]["header"] + "." + hmacKeyJWEJS["recipients"][0]["encrypted_key"] + "." + hmacKeyJWEJS["initialization_vector"]
				gcmCipher.update(aad.encode())
				cip, tag = gcmCipher.encrypt_and_digest(hmacKeyPlain.encode())
				#logging.info("expected ciphertext: " + b64urlencode(cip).decode())
				#logging.info("expected integrity_value: " + b64urlencode(tag).decode())

				hmacKeyJWEJS["recipients"][0]["integrity_value"] = b64urlencode(tag).decode()

				hmacKeyJWEJS_str = json.dumps(hmacKeyJWEJS)
				hmacKeyJWEJS_str = re.sub('[\s+]', '', hmacKeyJWEJS_str)
				hmacKeyEncStr = b64encode(hmacKeyJWEJS_str.encode()).decode()

				logging.info("encryptionkey after: " + encKeyJWEJS_str)
				logging.info("hmackey after: " + hmacKeyJWEJS_str)

			#logging.info("Signature after: " + parsedResponse["signature"])
			parsedHeaderData["keyresponsedata"]["keydata"]["hmackey"] = hmacKeyEncStr
			parsedHeaderData["keyresponsedata"]["keydata"]["encryptionkey"] = encKeyEncStr

			headerDataModified = json.dumps(parsedHeaderData).encode()
			parsedResponse["headerdata"] = b64encode(headerDataModified).decode()

			#logging.info("Signature before: " + parsedResponse["signature"])

			headerDataHash = SHA256.new(headerDataModified)
			parsedResponse["signature"] = b64encode(pkcs1_15.new(ProxySignKey).sign(headerDataHash)).decode()

			contentRest = b""
			if headerEndOffset != -1:
				contentRest = flow.response.content[headerEndOffset:]

			flow.response.content = json.dumps(parsedResponse).encode() + contentRest

			#logging.info(b64decode(parsedResponse["headerdata"]).decode())
			#logging.info(flow.response.content.decode())
		elif "ciphertext" in parsedHeaderData.keys() and MSLAESKey != None:
			iv = b64decode(parsedHeaderData["iv"])
			cipher = AES.new(MSLAESKey, AES.MODE_CBC, iv)

			cipherText = b64decode(parsedHeaderData["ciphertext"])
			try:
				plainText = unpad(cipher.decrypt(cipherText), 16)
				logging.info(plainText.decode())
			except ValueError:
				logging.error("Error: incorrect AES key")

		#logging.info("Number of chunks: " + str(len(parsedRespChunks)))
		for chunk in parsedRespChunks:
			if MSLAESKey == None:
				continue

			payload = json.loads(b64decode(chunk["payload"]))
			iv = b64decode(payload["iv"])
			cipher = AES.new(MSLAESKey, AES.MODE_CBC, iv)

			cipherText = b64decode(payload["ciphertext"])
			try:
				plainText = unpad(cipher.decrypt(cipherText), 16)
			except ValueError:
				logging.error("Error: incorrect AES key")
				continue

			plainJSON = None

			try:
				plainJSON = json.loads(plainText)
			except json.JSONDecodeError as e:
				plainJSON = json.loads(plainText[0:e.pos])

			#logging.info(plainText.decode())
			decoded = b64decode(plainJSON["data"])
			if "compressionalgo" in plainJSON.keys():
				if plainJSON["compressionalgo"] == "GZIP":
					decoded = gzip.decompress(decoded)
				elif plainJSON["compressionalgo"] == "LZW":
					decoded = lzw_decompress(decoded)

			logging.info(decoded.decode())

	elif "/cadmium-playercore" in flow.request.pretty_url:
		logging.info("Netflix cadmium player response")
		proxySignKeyStr = b64encode(ProxySignKey.publickey().exportKey("DER"))
		flow.response.content = flow.response.content.replace(ServerSignPubKey.encode(), proxySignKeyStr).replace(ServerSignPubKey2.encode(), proxySignKeyStr)
