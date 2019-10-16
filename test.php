<?PHP
// ==================================================================================================================
// =================== CREATE CSR =====================================================================================
// ==================================================================================================================

function test_download_cert(){
  $my_csrfile = test_create_csr(NULL,"1024","123456789","client");
  test_sign_csr("123456789",$my_csrfile,"30","client");
}
?>
<?PHP
function test_create_csr($my_cert_dn,$my_keysize,$my_passphrase, $device_type) {
$config=$_SESSION['config'];
$cert_dn=array();
$username = "Jiacheng MA";
$cert_dn["username"] = $username;
print "<h1>Creating Certificate Key</h1>";
print "PASSWORD:".$my_passphrase."<BR>";
$my_csrfile="";
$my_csrfile=$username;
$filename=base64_encode($my_csrfile);
print "CSR Filename : " . $my_csrfile."<BR>";
if ($my_device_type=='ca_cert') {
  $client_keyFile = $config['cakey'];
  $client_reqFile = $config['req_path'].$filename.".pem";  
}
else {
  $client_keyFile = $config['key_path'].$filename.".pem";
  $client_reqFile = $config['req_path'].$filename.".pem";
}
	
print "<h1>Creating Client CSR and Client Key</h1>";
print "<b>Checking your DN (Distinguished Name)...</b><br/>";
print "<pre>DN = ".var_export($cert_dn,1)."</pre>";
print "<b>Generating new key...</b><br/>";
print $my_keysize;
$my_new_config=array('config'=>$config['config'],'private_key_bits'=>(int)$my_keysize);
$privkey = openssl_pkey_new($my_new_config) or die('Fatal: Error creating Certificate Key');
print "Done<br/><br/>\n";

print "<b>Exporting encoded private key to file...</b><br/>";
openssl_pkey_export_to_file($privkey, $client_keyFile, $my_passphrase) or die ('Fatal: Error exporting Certificate Key to file');
print "Done<br/><br/>\n";

print "<b>Creating CSR...</b><br/>";
$my_csr = openssl_csr_new($cert_dn, $privkey,$config) or die('Fatal: Error creating CSR');
print "Done<br/><br/>\n";

print "<b>Exporting CSR to file...</b><br/>";
openssl_csr_export_to_file($my_csr, $client_reqFile) or die ('Fatal: Error exporting CSR to file');
print "Done<br/><br/>\n";

$my_details=openssl_csr_get_subject($my_csr);
$my_public_key_details=openssl_pkey_get_details(openssl_csr_get_public_key($my_csr));
?>
<?PHP
print "<h1>Client CSR and Key - Generated successfully</h1>";
return $my_csrfile.'.pem';
}

function test_sign_csr($passPhrase,$my_csrfile,$my_days,$my_device_type) {
$config=$_SESSION['config'];
$name = base64_encode(substr($my_csrfile, 0,strrpos($my_csrfile,'.')));
$ext = substr($my_csrfile, strrpos($my_csrfile,'.'));
$my_base64_csrfile=$name.$ext;
?>
<h1>Signing certificate request</h1>

<p>
<?PHP print "We will sign the requested CSR with this CA's key.";?>
</p>

<p>
Now signing certificate... Please wait...
</p>
<?php
print "<b>Loading CA key...</b><br/>";
$fp = fopen($config['cakey'], "r") or die('Fatal: Error opening CA Key'.$config['cakey']);
$my_key = fread($fp, filesize($config['cakey'])) or die('Fatal: Error reading CA Key'.$config['cakey']);
fclose($fp) or die('Fatal: Error closing CA Key'.$config['cakey']);
print "Done<br/><br/>\n";

print "<b>Decoding CA key...</b><br/>";
$my_ca_privkey = openssl_pkey_get_private($my_key, $passPhrase) or die('Fatal: Error decoding CA Key. Passphrase Incorrect');
print "Done<br/><br/>\n";

if (!($my_device_type=='ca_cert')) {
  print "<b>Loading CA Certificate...</b><br/>";
  $fp = fopen($config['cacert'], "r") or die('Fatal: Error opening CA Certificate'.$config['cacert']);
  $my_ca_cert = fread($fp, filesize($config['cacert'])) or die('Fatal: Error reading CA Certificate'.$config['cacert']);
  fclose($fp) or die('Fatal: Error closing CA Certificate'.$config['cacert']);
  print "Done<br/><br/>\n";
}
else 
  $my_ca_cert = NULL;
  
print "<b>Loading CSR from file...</b><br/>";
$fp = fopen($config['req_path'].$my_base64_csrfile, "r") or die('Fatal: Error opening CSR file'.$my_base64_csrfile);
$my_csr = fread($fp, filesize($config['req_path'].$my_base64_csrfile)) or die('Fatal: Error reading CSR file'.$my_base64_csrfile);
fclose($fp) or die('Fatal: Error closing CSR file '.$my_base64_csrfile);
print "Done<br/><br/>\n";

if ($my_device_type=='ca_cert') {
  print "<b>Deleting CSR file from Cert Store...</b><br/>";
  unlink($config['req_path'].$my_base64_csrfile) or die('Fatal: Error deleting CSR file'.$my_base64_csrfile);
  print "Done<br/><br/>\n";
}

print "<b>Signing CSR...</b><br/>";
$my_serial=sprintf("%04d",get_serial());
$my_scert = openssl_csr_sign($my_csr, $my_ca_cert, $my_ca_privkey, $my_days, $config, $my_serial) or die('Fatal: Error signing CSR.');
print "Done<br/><br/>\n";

print "<b>Exporting X509 Certificate...</b><br/>";
openssl_x509_export($my_scert, $my_x509_scert);
print "Done<br/><br/>\n";

$my_x509_parse=openssl_x509_parse($my_x509_scert);
$my_hex_serial=dechex($my_serial);
if (is_int((strlen($my_hex_serial)+1)/2))
 $my_hex_serial="0".$my_hex_serial;
//$index_line="V\t".$my_x509_parse['validTo']."\t\t".$my_serial."\tunknown\t".$my_x509_parse['name'];
$my_index_name="/C=".$my_x509_parse['subject']['C']."/ST=".$my_x509_parse['subject']['ST']."/L=".$my_x509_parse['subject']['L']."/O=".$my_x509_parse['subject']['O']."/OU=".$my_x509_parse['subject']['OU']."/CN=".$my_x509_parse['subject']['CN']."/emailAddress=".$my_x509_parse['subject']['emailAddress'];
$index_line="V\t".$my_x509_parse['validTo']."\t\t".$my_hex_serial."\tunknown\t".$my_index_name;

//Patern to match the index lines
$pattern = '/(\D)\t(\d+[Z])\t(\d+[Z])?\t(\d+)\t(\D+)\t(.+)/'; 

//Check to see if the certificate already exists in the Index file (ie. If someone clicks refresh on the webpage after creating a cert)
//$my_valid_cert=does_cert_exist($my_index_name);
$my_valid_cert = 0;
if ($my_valid_cert==0) {
  print "<b>Saving X509 Certificate...</b><br/>";
  if ($my_device_type=='ca_cert') 
    $my_scertfile = $config['cacert'];
  else
    $my_scertfile = $config['cert_path'].$my_base64_csrfile;
  if ($fp = fopen($my_scertfile, 'w') or die('Fatal: Error opening Signed Cert X509 file $my_scertfile') ) {
	fputs($fp, $my_x509_scert)  or die('Fatal: Error writing Signed Cert X509 file $my_scertfile') ;
	fclose($fp)  or die('Fatal: Error closing Signed Cert X509 file $my_scertfile') ;
  }
  if ( !($my_device_type=='ca_cert') ) {
    $my_scertfile = $config['newcert_path'].$my_serial.".pem";
    if ($fp = fopen($my_scertfile, 'w') or die('Fatal: Error opening Signed Cert X509 file $my_scertfile') ) {
	  fputs($fp, $my_x509_scert)  or die('Fatal: Error writing Signed Cert X509 file $my_scertfile') ;
	  fclose($fp)  or die('Fatal: Error closing Signed Cert X509 file $my_scertfile') ;
    }
    print "Done\n<br>\n";
    print "<b>Updating Index File...</b><br>";
    $my_index_handle = fopen($config['index'], "a") or die('Fatal: Unable to open Index file for appending');
    fwrite($my_index_handle,$index_line."\n") or die('Fatal: Unable to append data to end of Index file');
    fclose($my_index_handle) or die('Fatal: Unable to close Index file');
  }
  print "Done";
  print "<br><br>";
  print "<b>Download Certificate:</b>\n<br>\n<br>\n";

?>
<form action="index.php" method="post">
<input type="hidden" name="menuoption" value="download_cert">
<input type="hidden" name="cert_name" value="<?PHP if ($my_device_type=='ca_cert') print 'zzTHISzzCAzz'; else print $my_csrfile;?>">
<input type="submit" value="Download Signed Certificate">
</form>
<BR>
<form action="index.php" method="post">
<input type="hidden" name="menuoption" value="download_cert">
<input type="hidden" name="cert_name" value="<?PHP print 'zzTHISzzCAzz';?>">
<input type="submit" value="Download CA Trusted Root Certificate">
</form>
<BR><BR>
<?PHP
  print "<b>Your certificate:</b>\n<pre>$my_x509_scert</pre>\n";
?>
<h1>Successfully signed certificate request with CA key.</h1>
<?PHP

if ($my_device_type=='subca_cert') {
  print "Creating Sub-CA certificate Store...\n<br>";
  $my_cert_dn=openssl_csr_get_subject($my_csr) or die('Fatal: Getting Subject details from CSR');
  create_cert_store($config['certstore_path'], $my_cert_dn['CN']);
  print "Copying Sub CA Certificate over...\n<br>";
  copy($config['cert_path'].$my_base64_csrfile,$config['certstore_path'].$my_cert_dn['CN'].'/cacert.pem') or die('Fatal: Unable to copy sub-ca cacert.pem from Existing CA to Sub-CA Certificate Store');
  print "Done\n<br>";
  print "Copying Sub CA Certificate over...\n<br>";
  copy($config['key_path'].$my_base64_csrfile,$config['certstore_path'].$my_cert_dn['CN'].'/cacert.key') or die('Fatal: Unable to copy sub-ca cakey.pem from Existing CA to Sub-CA Certificate Store');
  print "Done\n<br>";
}

  }
else 
  print "<h1>".$my_x509_parse['name']." already exists in the Index file and is Valid.</h1>";

} //end of function sign_cert()

?>


