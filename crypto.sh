#! /bin/bash

ENCRYPT=0
DECRYPT=0
SAVE_POSITION=()
RED='\033[0;31m'
NC='\033[0m' # No Color
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
TAR_FILE_BINARY=`which tar`
OPENSSL_FILE_BINARY=`which openssl`
RM_FILE_BINARY=`which rm`
CONFIDENTIALITY=0
INTEGRITY=0
AUTHENTICITY=0
KEY_HASH_VERIFY=0
plain_text_encrypted_filename="plain_text_encrypted.enc"
hashed_plain_text="plain_text.hash"

check_if_file_exists () {
filename=$1
  if [ ! -f $filename ]; then
    #echo -e "\n \n $filename not found!"
    echo "0"
  else
    echo "1"
  fi
}

implement_confidentiality () {

  # Create secret key file
  $OPENSSL_FILE_BINARY rand -base64 128 > secret_file.key
  #set -x
  # Encrypt secret file with public key of reciever
  status_of_encrypt=$($OPENSSL_FILE_BINARY rsautl -encrypt -inkey $1 -pubin -in secret_file.key -out secret_file.enc 2>&1)
  size_of_encrypt_status=${#status_of_encrypt}

  # if encryption failed then delete secret key
  if [ $size_of_encrypt_status != 0 ]
  then
    $RM_FILE_BINARY secret_file.key
    echo $status_of_encrypt
    exit 1;
  fi

  # Encrypt the plaintext with secret key
  status_of_plain_text_encrypt=$($OPENSSL_FILE_BINARY enc -aes-256-cbc -salt -in $2 -out $plain_text_encrypted_filename -pass file:./secret_file.key 2>&1)
}

implement_integrity () {

  # Hashing the plaintext with sha512
  $OPENSSL_FILE_BINARY dgst -sha512 $1 | awk {'print $2'} > plain_text.hash

  # Hashing the secret key with sha512
  $OPENSSL_FILE_BINARY dgst -sha512 secret_file.key | awk {'print $2'} > secret_file.hash

}

implement_authenticity () {

  TAR_FILE="intermediate.tar"
  SIGNED_TAR_FILE="$TAR_FILE.sign"
  final_tar=$2

  # Creating a zip of all encrypted things and hashes, also delete the files which are tared.
  $TAR_FILE_BINARY --remove-files -cf $TAR_FILE $plain_text_encrypted_filename ./secret_file.enc ./secret_file.hash $hashed_plain_text

  # Digitally sign the tar file with sender's private key
  digital_sign_status=$($OPENSSL_FILE_BINARY dgst -sha512 -sign $1 -out $SIGNED_TAR_FILE $TAR_FILE)

  # IF not executed properly then check the exit status data if not 0 then delete traces.
  size_of_digital_sign_status=${#digital_sign_status}

  # if encryption failed then delete secret key
  if [ $size_of_digital_sign_status != 0 ]
  then
    $RM_FILE_BINARY -rf $TAR_FILE
    echo $digital_sign_status
    exit 1;
  fi

  # Creating a new tar file for signature and rest of the content.
  $TAR_FILE_BINARY --remove-files -cf $final_tar $TAR_FILE $SIGNED_TAR_FILE

  # Delete original secret key so no traces of ecnryption are left
  $RM_FILE_BINARY -rf ./secret_file.key
}

verify_authenticity () {

  final_tar=$1
  TAR_FILE="intermediate.tar"
  SIGNED_TAR_FILE="$TAR_FILE.sign"
  CORRECT_VERIFICATION="Verified OK"

  # Untar the outer tar file
   $TAR_FILE_BINARY -xf $final_tar -C ./

  # Verify the digital signature using sender's public key
  VERIFICATION_MESSAGE=`$OPENSSL_FILE_BINARY dgst -sha512 -verify $2 -signature $SIGNED_TAR_FILE $TAR_FILE`

  if [ "$VERIFICATION_MESSAGE" == "$CORRECT_VERIFICATION" ]
  then
    # Authenticity Passed
    AUTHENTICITY=1
  else
    # Not Authenticated hence delete traces.
    echo -e "${RED}AUTHENTICITY PROBLEM : Signature not verified${NC}"
    $RM_FILE_BINARY -rf $plain_text_encrypted_filename ./secret_file.enc ./secret_file.hash ./plain_text.hash
    exit 1;
  fi

}

verify_confidentiality () {

  KEY="key"

  # Untar intermediate tar file
  $TAR_FILE_BINARY -xf intermediate.tar -C ./

  # Decrypt the secret key with reciever's private key
  $OPENSSL_FILE_BINARY rsautl -decrypt -inkey $1 -in secret_file.enc -out secret_file.key

  verify_integrity $KEY

  # Decrypt the Encrypted plain text with decrpted secret key
  status_of_decrypt=$(openssl enc -d -aes-256-cbc -in $plain_text_encrypted_filename -out $2 -pass file:./secret_file.key 2>&1)

  # IF not executed properly then check the exit status data if not 0 then delete traces.
  size_of_status=${#status_of_decrypt}

  if [ $size_of_status != 0 ]
  then
    echo -e "${RED}CONFIDENTIALITY CHECK FAILED : ${NC} Encrypted file couldnot be decrypted with this key"
    $RM_FILE_BINARY -rf secret_file.hash secret_file.enc plain_text.hash plain_text_encrypted.enc intermediate.tar.sign intermediate.tar secret_file.key
    echo $status_of_decrypt
    exit 1;
  else
    # Confidentiality passed
    CONFIDENTIALITY=1
  fi

}

verify_integrity () {

  if [ $1 == "key" ]
  then
    # Compare hash of decrypted key with key_bin.hash
    $OPENSSL_FILE_BINARY dgst -sha512 secret_file.key | awk {'print $2'} > secret_file_verify.hash
    ORIGINAL_HASH="secret_file.hash"
    VERIFICATION_TARGET_HASH="secret_file_verify.hash"
    if cmp -s "$ORIGINAL_HASH" "$VERIFICATION_TARGET_HASH"; then
      # Secret Key verified properly
      KEY_HASH_VERIFY=1
    else
      # Key not verified properly hence deleting traces
      echo -e "${RED}SECRET key not retrieved properly${NC}"
      exit 1;
    fi
  else
    # Compare hash of decrypted file with hash of plain_text
    $OPENSSL_FILE_BINARY dgst -sha512 $2 | awk {'print $2'} > plain_text_verify.hash
    ORIGINAL_FILE_HASH="plain_text.hash"
    VERIFICATION_FILE_TARGET_HASH="plain_text_verify.hash"
    if cmp -s "$ORIGINAL_FILE_HASH" "$VERIFICATION_FILE_TARGET_HASH"; then
      # Integrity passed
      INTEGRITY=1
    else
      # Integrity check failed hence delete traces.
      echo -e "${RED}INTEGRITY CHECK FAILED : ${NC} Plain text file could not be matched with original text file"
      $RM_FILE_BINARY -rf secret_file.hash secret_file.enc plain_text.hash plain_text_encrypted.enc intermediate.tar.sign intermediate.tar secret_file_verify.hash secret_file.key plain_text_verify.hash
      exit 1;
    fi
  fi


}



if [[ $# != 5 ]] # Wrong number of arguments
then
  echo -e "${RED}###################### ERROR ###################### \n"
  echo -e "${YELLOW}Please give valid number of arguments: \n\n${NC}"
  echo -e "${GREEN}**** USAGE **** \n"
  echo -e "${BLUE}./crypto.sh -e <receiver_public_key_file> <sender_private_key_file> \
<plaintext_file> <encrypted_file> for Encryption${NC}"
  echo -e "${BLUE}./crypto.sh -d <receiver_private_key_file> <sender_public_key_file> \
<encrypted_file> <decrypted_file> for Decryption \n\n\n${NC}"
else
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -e|--encrypt)
    ENCRYPT=1
    shift # past encryption flag
    receiver_public_key_file=$1 # save location of receiver_public_key_file
    sender_private_key_file=$2  # save location of sender_private_key_file
    plaintext_file=$3           # save location of plaintext_file
    encrypted_file=$4

    ## Check if the files exist that are expected as input for encryption
    check_receiver_public_key_file=`check_if_file_exists $receiver_public_key_file`
    check_sender_private_key_file=`check_if_file_exists $sender_private_key_file`
    check_plaintext_file=`check_if_file_exists $plaintext_file`
    file_check_result=$(($check_plaintext_file + $check_sender_private_key_file + $check_receiver_public_key_file))

    if [ $file_check_result == 3 ]
    then
      #echo "start encryption process"
      #set -x
      implement_confidentiality $receiver_public_key_file $plaintext_file $encrypted_file
      implement_integrity $plaintext_file
      implement_authenticity $sender_private_key_file $encrypted_file $plaintext_file
      filename=$plaintext_file
      #echo "Encryption Completed"
    else
      echo -e "\n \n File(s) not found!"
    fi
    ;;
    -d|--decrypt)
    DECRYPT=1
    shift # past decryption flag
    receiver_private_key_file=$1 # save location of receiver_public_key_file
    sender_public_key_file=$2    # save location of sender_private_key_file
    encrypted_file=$3            # save location of encrypted_file
    decrypted_file=$4            # save location of decrypted_file

    ## Check if the files exist that are expected as input for decryption
    check_receiver_private_key_file=`check_if_file_exists $receiver_private_key_file`
    check_sender_public_key_file=`check_if_file_exists $sender_public_key_file`
    check_encrypted_file=`check_if_file_exists $encrypted_file`
    check_decrypted_file=`check_if_file_exists $decrypted_file`
    file_check_result=$(($check_receiver_private_key_file + $check_sender_public_key_file + $check_encrypted_file))

    if [ $file_check_result == 3 ]
    then
      #echo "start decryption process"
      #set -x
      FILE="text"
      verify_authenticity $encrypted_file $sender_public_key_file
      verify_confidentiality $receiver_private_key_file $decrypted_file
      verify_integrity $FILE $decrypted_file
      CIA_FINAL_CHECK=$(($CONFIDENTIALITY + $INTEGRITY + $AUTHENTICITY))
      if [ $CIA_FINAL_CHECK == 3 ]
      then
        #echo -e "${GREEN}CONGRATULATIONS : Decryption Successful!!${NC}"
        $RM_FILE_BINARY -rf secret_file.hash secret_file.enc plain_text.hash plain_text_encrypted.enc intermediate.tar.sign intermediate.tar secret_file_verify.hash secret_file.key plain_text_verify.hash $encrypted_file
      fi
    else
      echo -e "\n \n File(s) not found!"
    fi
    ;;
    *)    # unknown option
    SAVE_POSITION+=("$1") # save it in an array for later
    shift # past argument

    ;;
esac
done
set -- "${SAVE_POSITION[@]}" # restore SAVE_POSITION parameters
fi
