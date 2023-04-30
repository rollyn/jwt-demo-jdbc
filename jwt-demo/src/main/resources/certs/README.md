<p>
openssl genrsa -out keypair.pem 2048 <br/>
openssl rsa -in keypair.pem -pubout -out public.pem <br/>
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem <br/>
</p>
<p>
Generated files: <br/>
keypair.pem - Keypair to extract private/public pem (can delete after creating private/public pem)<br/>
public.pem <br/> 
private.pen <br/>
</p>

<p>
curl -I http://localhost:8080 - throws 401<br/>
curl --location --request POST 'http://localhost:8080/token' --header 'Authorization: Basic Z3Vlc3Q6cGFzc3dvcmQ='<br/>
username:password - base64 encode <br/>
<br/>
curl --location --request GET 'http://localhost:8080' \
--header 'Authorization: Bearer <token>'

</p>
