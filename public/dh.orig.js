function loadXMLDoc(client_pub_g, sjcl, SK_base64) {
  var xmlhttp;
  var encrypted;
  if (window.XMLHttpRequest) {
    xmlhttp = new XMLHttpRequest();
  } else {
    xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
  }
  xmlhttp.onreadystatechange = function() {

    	if (this.readyState == 4 && this.status == 200) {

    window.location = 'final.html';
    		
    }
  };
  xmlhttp.open("GET", "client_pub.html?cl=" + encodeURIComponent(client_pub_g), true);
  xmlhttp.send();
  return 0;
}



function test(){
	var curve = sjcl.ecc.curves.k256;
	var client_pair = sjcl.ecc.elGamal.generateKeys(curve, 1); 
	var client_pub = client_pair.pub, client_sec = client_pair.sec;
	client_pub_64 = sjcl.codec.base64.fromBits(client_pub.get().x.concat(client_pub.get().y));
	
	/*create new key, to test for fixed keys*/
	var client_pair_new = sjcl.ecc.elGamal.generateKeys(curve, 1); 
	var client_pub_new = client_pair_new.pub;
	client_pub_64_new = sjcl.codec.base64.fromBits(client_pub_new.get().x.concat(client_pub_new.get().y));
	
	if (client_pub_64_new == client_pub_64){
		throw new Error("The same key was generated twice!");
	}
	
	client_sec_64 = sjcl.codec.base64.fromBits(client_sec.get());
	client_pub_g = client_pub.get();
	var client_pub_base64_x = sjcl.codec.base64.fromBits(client_pub_g.x);
	var client_pub_base64_y = sjcl.codec.base64.fromBits(client_pub_g.y);
	var pub_server_hex_x = <INSERT_pub_server_hex_x_HERE>;
    var pub_server_hex_y = <INSERT_pub_server_hex_y_HERE>;
    var pub_server_key = new sjcl.ecc.elGamal.publicKey(curve, sjcl.codec.hex.toBits(pub_server_hex_x.concat(pub_server_hex_y)));
	var shared_key = client_pair.sec.dhJavaEc(pub_server_key);		//The derived key is the SHA-256 hash of the shared secret point.
	var SK_base64 = sjcl.codec.base64.fromBits(shared_key);
	
	sessionStorage.SK_base64 = SK_base64;
	shared_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	client_sec = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	client_sec_64 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	client_pair = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	not_used = loadXMLDoc(sjcl.codec.base64.fromBits(client_pub_g.x.concat(client_pub_g.y)), sjcl, SK_base64);
	SK_base64 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

}

function loaded() {
	sjcl.random.setDefaultParanoia(10);
	sjcl.random.startCollectors();
}