def exchange_code_for_token(self, code: str) -> Optional[Dict]:
    """
    Exchange authorization code for access token
    """
    print("=== EXCHANGE_CODE_FOR_TOKEN CALLED ===", flush=True)
    print(f"=== CODE: {code[:20]} ===", flush=True)
    print(f"=== CLIENT_ID: {self.client_id} ===", flush=True)
    print(f"=== CLIENT_SECRET: {self.client_secret[:10]}... ===", flush=True)
    print(f"=== REDIRECT_URI: {self.redirect_uri} ===", flush=True)
    print(f"=== TOKEN_URL: {TOKEN_URL} ===", flush=True)
    
    payload = {
        "client_id": self.client_id,
        "client_secret": self.client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": self.redirect_uri,
    }

    try:
        print(f"=== PAYLOAD: {payload} ===", flush=True)
        print(f"=== SENDING POST REQUEST ===", flush=True)
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        response = requests.post(TOKEN_URL, data=payload, headers=headers, timeout=10)
        
        print(f"=== RESPONSE STATUS: {response.status_code} ===", flush=True)
        print(f"=== RESPONSE CONTENT_TYPE: {response.headers.get('content-type')} ===", flush=True)
        print(f"=== RESPONSE TEXT (FULL): {response.text} ===", flush=True)
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                print(f"=== SUCCESS! Token keys: {list(token_data.keys())} ===", flush=True)
                return token_data
            except Exception as json_err:
                print(f"=== JSON PARSE FAILED: {json_err} ===", flush=True)
                return None
        else:
            print(f"=== ERROR: Status {response.status_code} ===", flush=True)
            return None
    except Exception as e:
        print(f"=== EXCEPTION: {e} ===", flush=True)
        import traceback
        print(traceback.format_exc(), flush=True)
        return None
