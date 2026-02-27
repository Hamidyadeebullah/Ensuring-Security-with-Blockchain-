import rsa

def generate_keys():
    print("Generating RSA Key Pair (512-bit)...")
    public_key, private_key = rsa.newkeys(512)
    
    with open("public.pem", "wb") as f:
        f.write(public_key.save_pkcs1())
        
    with open("private.pem", "wb") as f:
        f.write(private_key.save_pkcs1())
        
    print("Keys generated successfully: 'public.pem' and 'private.pem'")

if __name__ == "__main__":
    generate_keys()