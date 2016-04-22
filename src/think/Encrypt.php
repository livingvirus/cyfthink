<?php
namespace think;

class Encrypt
{
    public $encryption_key = '';
    public $_hash_type     = 'sha1';
    public $_mcrypt_cipher = MCRYPT_CAST_256; //RIJNDAEL_128
    public $_mcrypt_mode   = MCRYPT_MODE_CFB;

    /**
     * Constructor
     *
     * Simply determines whether the mcrypt library exists.
     *
     */
    public function __construct()
    {
        if (function_exists('mcrypt_encrypt') === false) {
            throw new \Exception('The Encrypt library requires the Mcrypt extension.');
        }
    }

    // --------------------------------------------------------------------

    /**
     * Fetch the encryption key
     *
     * Returns it as MD5 in order to have an exact-length 128 bit key.
     * Mcrypt is sensitive to keys that are not the correct length
     *
     * @access    public
     * @param    string
     * @return    string
     */
    public function getKey($key = '')
    {
        if ($key == '') {
            if ($this->encryption_key != '') {
                return $this->encryption_key;
            }

            $key = \think\Config::get('encryption_key');

        }
        return md5($key);
    }

    // --------------------------------------------------------------------

    /**
     * Set the encryption key
     *
     * @access    public
     * @param    string
     * @return    void
     */
    public function setKey($key = '')
    {
        $this->encryption_key = $key;
    }

    // --------------------------------------------------------------------

    /**
     * Encode
     *
     * Encodes the message string using bitwise XOR encoding.
     * The key is combined with a random hash, and then it
     * too gets converted using XOR. The whole thing is then run
     * through mcrypt using the randomized key. The end result
     * is a double-encrypted message string that is randomized
     * with each call to this function, even if the supplied
     * message and key are the same.
     *
     * @access    public
     * @param    string    the string to encode
     * @param    string    the key
     * @return    string
     */
    public function encode($string, $key = '')
    {
        $key = $this->getKey($key);
        $enc = $this->mcryptEncode($string, $key);

        return base64_encode($enc);
    }

    // --------------------------------------------------------------------

    /**
     * Decode
     *
     * Reverses the above process
     *
     * @access    public
     * @param    string
     * @param    string
     * @return    string
     */
    public function decode($string, $key = '')
    {
        $key = $this->getKey($key);

        if (preg_match('/[^a-zA-Z0-9\/\+=]/', $string)) {
            return false;
        }

        $dec = base64_decode($string);

        if (($dec = $this->mcryptDecode($dec, $key)) === false) {
            return false;
        }

        return $dec;
    }

    // --------------------------------------------------------------------

    /**
     * Encode from Legacy
     *
     * Takes an encoded string from the original Encryption class algorithms and
     * returns a newly encoded string using the improved method added in 2.0.0
     * This allows for backwards compatibility and a method to transition to the
     * new encryption algorithms.
     *
     * For more details, see http://codeigniter.com/user_guide/installation/upgrade_200.html#encryption
     *
     * @access    public
     * @param    string
     * @param    int        (mcrypt mode constant)
     * @param    string
     * @return    string
     */
    public function encodeFromLegacy($string, $legacy_mode = MCRYPT_MODE_ECB, $key = '')
    {
        // decode it first
        // set mode temporarily to what it was when string was encoded with the legacy
        // algorithm - typically MCRYPT_MODE_ECB
        $current_mode = $this->_get_mode();
        $this->setMode($legacy_mode);

        $key = $this->getKey($key);

        if (preg_match('/[^a-zA-Z0-9\/\+=]/', $string)) {
            return false;
        }

        $dec = base64_decode($string);

        if (($dec = $this->mcryptDecode($dec, $key)) === false) {
            return false;
        }

        $dec = $this->_xor_decode($dec, $key);

        // set the mcrypt mode back to what it should be, typically MCRYPT_MODE_CBC
        $this->setMode($current_mode);

        // and re-encode
        return base64_encode($this->mcryptEncode($dec, $key));
    }

    // --------------------------------------------------------------------

    /**
     * XOR Decode
     *
     * Takes an encoded string and key as input and generates the
     * plain-text original message
     *
     * @access    private
     * @param    string
     * @param    string
     * @return    string
     */
    public function _xor_decode($string, $key)
    {
        $string = $this->_xor_merge($string, $key);

        $dec = '';
        for ($i = 0; $i < strlen($string); $i++) {
            $dec .= (substr($string, $i++, 1) ^ substr($string, $i, 1));
        }

        return $dec;
    }

    // --------------------------------------------------------------------

    /**
     * XOR key + string Combiner
     *
     * Takes a string and key as input and computes the difference using XOR
     *
     * @access    private
     * @param    string
     * @param    string
     * @return    string
     */
    public function _xor_merge($string, $key)
    {
        $hash = $this->hash($key);
        $str  = '';
        for ($i = 0; $i < strlen($string); $i++) {
            $str .= substr($string, $i, 1) ^ substr($hash, ($i % strlen($hash)), 1);
        }

        return $str;
    }

    // --------------------------------------------------------------------

    /**
     * Encrypt using Mcrypt
     *
     * @access    public
     * @param    string
     * @param    string
     * @return    string
     */
    public function mcryptEncode($data, $key)
    {
        $init_size = mcrypt_get_iv_size($this->_get_cipher(), $this->_get_mode());
        $init_vect = mcrypt_create_iv($init_size, MCRYPT_RAND);
        return $this->_add_cipher_noise($init_vect . mcrypt_encrypt($this->_get_cipher(), $key, $data, $this->_get_mode(), $init_vect), $key);
    }

    // --------------------------------------------------------------------

    /**
     * Decrypt using Mcrypt
     *
     * @access    public
     * @param    string
     * @param    string
     * @return    string
     */
    public function mcryptDecode($data, $key)
    {
        $data      = $this->_remove_cipher_noise($data, $key);
        $init_size = mcrypt_get_iv_size($this->_get_cipher(), $this->_get_mode());

        if ($init_size > strlen($data)) {
            return false;
        }

        $init_vect = substr($data, 0, $init_size);
        $data      = substr($data, $init_size);
        return rtrim(mcrypt_decrypt($this->_get_cipher(), $key, $data, $this->_get_mode(), $init_vect), "\0");
    }

    // --------------------------------------------------------------------

    /**
     * Adds permuted noise to the IV + encrypted data to protect
     * against Man-in-the-middle attacks on CBC mode ciphers
     * http://www.ciphersbyritter.com/GLOSSARY.HTM#IV
     *
     * Function description
     *
     * @access    private
     * @param    string
     * @param    string
     * @return    string
     */
    public function _add_cipher_noise($data, $key)
    {
        $keyhash = $this->hash($key);
        $keylen  = strlen($keyhash);
        $str     = '';

        for ($i = 0, $j = 0, $len = strlen($data); $i < $len; ++$i, ++$j) {
            if ($j >= $keylen) {
                $j = 0;
            }

            $str .= chr((ord($data[$i]) + ord($keyhash[$j])) % 256);
        }

        return $str;
    }

    // --------------------------------------------------------------------

    /**
     * Removes permuted noise from the IV + encrypted data, reversing
     * _add_cipher_noise()
     *
     * Function description
     *
     * @access    public
     * @param    type
     * @return    type
     */
    public function _remove_cipher_noise($data, $key)
    {
        $keyhash = $this->hash($key);
        $keylen  = strlen($keyhash);
        $str     = '';

        for ($i = 0, $j = 0, $len = strlen($data); $i < $len; ++$i, ++$j) {
            if ($j >= $keylen) {
                $j = 0;
            }

            $temp = ord($data[$i]) - ord($keyhash[$j]);

            if ($temp < 0) {
                $temp = $temp + 256;
            }

            $str .= chr($temp);
        }

        return $str;
    }

    // --------------------------------------------------------------------

    /**
     * Set the Mcrypt Cipher
     *
     * @access    public
     * @param    constant
     * @return    string
     */
    public function setCipher($cipher)
    {
        $this->_mcrypt_cipher = $cipher;
    }

    // --------------------------------------------------------------------

    /**
     * Set the Mcrypt Mode
     *
     * @access    public
     * @param    constant
     * @return    string
     */
    public function setMode($mode)
    {
        $this->_mcrypt_mode = $mode;
    }

    // --------------------------------------------------------------------

    /**
     * Get Mcrypt cipher Value
     *
     * @access    private
     * @return    string
     */
    public function _get_cipher()
    {
        if ($this->_mcrypt_cipher == '') {
            $this->_mcrypt_cipher = MCRYPT_RIJNDAEL_256;
        }

        return $this->_mcrypt_cipher;
    }

    // --------------------------------------------------------------------

    /**
     * Get Mcrypt Mode Value
     *
     * @access    private
     * @return    string
     */
    public function _get_mode()
    {
        if ($this->_mcrypt_mode == '') {
            $this->_mcrypt_mode = MCRYPT_MODE_CBC;
        }

        return $this->_mcrypt_mode;
    }

    // --------------------------------------------------------------------

    /**
     * Set the Hash type
     *
     * @access    public
     * @param    string
     * @return    string
     */
    public function setHash($type = 'sha1')
    {
        $this->_hash_type = ($type != 'sha1' and $type != 'md5') ? 'sha1' : $type;
    }

    // --------------------------------------------------------------------

    /**
     * Hash encode a string
     *
     * @access    public
     * @param    string
     * @return    string
     */
    public function hash($str)
    {
        return ($this->_hash_type == 'sha1') ? sha1($str) : md5($str);
    }
}
