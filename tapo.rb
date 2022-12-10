require 'openssl'
require 'base64'
require 'digest/sha1'
require 'http'
class TapoResult
   attr_reader :watt, :kwh
   def initialize(watt, kwh)
     @watt = watt
     @kwh = kwh
   end
end

class TPLinkCipher
  def initialize(iv, key)
    @iv = iv
    @key = key
  end
  
  def encrypt(text)
    input = pkcs7_encode(text)
    cipher = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
    cipher.encrypt()
    cipher.key = @key
    cipher.iv = @iv
    encrypted = cipher.update(text) + cipher.final
    return Base64.encode64(encrypted)
  end
  
  def decrypt(base64)
    cipher = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
    cipher.decrypt()
    cipher.key = @key
    cipher.iv = @iv
    padded = cipher.update(Base64.decode64(base64)) + cipher.final
    pkcs7_decode(padded)
  end
  
  def pkcs7_decode(text)
    block_size = 16
    pad = text[-1].ord
    pad = 0 if (pad < 1 || pad > block_size)
    size = text.size - pad
    text[0...size]
  end
  def pkcs7_encode(text)
    block_size = 16
    amount_to_pad = block_size - (text.length % block_size)
    amount_to_pad = block_size if amount_to_pad == 0
    pad_chr = amount_to_pad.chr
    "#{text}#{pad_chr * amount_to_pad}"
  end
  
end

class P100
  
  @cookie_name = "TP_SESSIONID"
  
  def initialize(ip, email, password)
    @ip = ip
    @email = email
    @password = password
    encrypt_credentials()
    generate_keys()
  end
  
  def encrypt_credentials()
    @encrypted_password = Base64.encode64(@password)
    @encrypted_email = Base64.encode64(sha_digest_username(@email))
  end
  
  def sha_digest_username(text)
    return Digest::SHA1::hexdigest(text)
  end
  
  def generate_keys()
    rsa = OpenSSL::PKey::RSA.new(1024)
    @private_key = rsa
    @public_key = rsa.public_key.to_pem.gsub(/\n$/,"")
  end
  
  def handshake()
    payload = {"method"=> "handshake", "params" => {"key" => @public_key, "requestTimeMils" => 0}}
    response = HTTP.post("http://#{@ip}/app", :json => payload)
    json = JSON.parse(response)
    if json["error_code"] == 0
      # puts "Handshake OK" 
      handshake_key = json["result"]["key"]
      # puts "Handshake key:#{handshake_key}"
      @tplink_cipher = decode_handshake_key(handshake_key)
      @cookie = response.cookies.cookies.find{|a| a.name == "TP_SESSIONID"}.value
    end
    
  end
  
  def decode_handshake_key(key)
    key_bytes = Base64.decode64(key)
    our_key = @private_key
    bytes = our_key.private_decrypt(key_bytes)
    tp_link_key = bytes[0...16]
    tp_link_iv = bytes[16...32]
    @tp_link_cipher = TPLinkCipher.new(tp_link_iv, tp_link_key)    
  end
  
  def login
    payload = {"method" => "login_device",
			"params" => {
				"password" => @encrypted_password,
				"username" => @encrypted_email
			},
			"requestTimeMils" => 0
    }
    # puts payload
    encrypted = @tp_link_cipher.encrypt(payload.to_json)
		passthrough_payload = {
			"method" =>"securePassthrough",
			"params"=> {
				"request": encrypted
			}
		}
    # puts passthrough_payload
    response = HTTP.cookies("TP_SESSIONID" => @cookie).post("http://#{@ip}/app", :json => passthrough_payload)
    json = JSON.parse(response)
    if (json["error_code"] == 0)
      encrypted = json["result"]["response"]
      decrypted = @tp_link_cipher.decrypt(encrypted)
      json = JSON.parse(decrypted)
      if (json["error_code"] == 0)
        @token = json["result"]["token"]        
      end
    end
  end
  
  
  
  def get_energy_usage
    payload = {"method" => "get_energy_usage",
			"requestTimeMils" => 0
    }
    # puts payload
    encrypted = @tp_link_cipher.encrypt(payload.to_json)
		passthrough_payload = {
			"method" =>"securePassthrough",
			"params"=> {
				"request": encrypted
			}
		}
    # puts passthrough_payload
    response = HTTP.cookies("TP_SESSIONID" => @cookie).post("http://#{@ip}/app?token=#{@token}", :json => passthrough_payload)
    json = JSON.parse(response)
    if (json["error_code"] == 0)
      encrypted = json["result"]["response"]
      decrypted = @tp_link_cipher.decrypt(encrypted)
      json = JSON.parse(decrypted)
      if (json["error_code"] == 0)
        return TapoResult.new(json["result"]["current_power"] / 1000.0 , json["result"]["month_energy"] / 1000.0)
      end
    end
    return nil
  end
end

