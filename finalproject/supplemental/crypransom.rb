# COMP 116 Supplemental Material
# example ruby script which encrypts a 
# file using AES-256 then encrypts the AES
# key with an RSA-2048 bit public key

require 'openssl'
require 'base64'

def encrypt_aes()
	 aes = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
	 aes.encrypt
	 key = aes.random_key
	 iv = aes.random_iv

	 buffer = ""

	 File.open("test.png", "wb") do |outf|
	 		File.open("test.png", "rb") do |inf|
	 			while inf.read(4096, buffer)
	 				
	 				# encrypts
	 				outf << aes.update(buffer)
	 			end
	 			outf << aes.final
	 		end
	end

	# write the key and the iv to the directory
	open 'key.aes', 'w' do |io| io.write key end
	open 'iv.aes' , 'w' do |io| io.write key end
end

def encrypt_rsa()
	key = OpenSSL::PKey::RSA.new(2048)
	pub = key.public_key

	encrypted = Base64.encode64(key.public_key.public_encrypt(File.read("key.aes")))

	open 'encrypted_aes.pem', 'w' do |io| io.write encrypted end
	open 'private_key.pem', 'w' do |io| io.write key.to_pem end
	open 'public_key.pem', 'w' do |io| io.write key.public_key.to_pem end
	

end 

encrypt_aes()
encrypt_rsa()