<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class EncryptController extends Controller
{

    private $_config;

    var $config_file;

    private $rsa_config = array(
        //公钥
        'public_key' => '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+WiouLXlITohBzGZSAR0vEZOz
xg5PgvbX6/etLpP4hUAgIDtj02VFmrU5VuG9+YDTgam5ahvjsZUAs3Uxmbl4tdw8
IdqoTlHfbqoiHEwiKVQ8RmQEDrEJHMRA9PLL4AFSt4WKnv63N9XnEw5SIHUaL1dV
l8ywvRBr8WrymdD14wIDAQAB
-----END PUBLIC KEY-----',
        //私钥
        'private_key' => '-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC+WiouLXlITohBzGZSAR0vEZOzxg5PgvbX6/etLpP4hUAgIDtj
02VFmrU5VuG9+YDTgam5ahvjsZUAs3Uxmbl4tdw8IdqoTlHfbqoiHEwiKVQ8RmQE
DrEJHMRA9PLL4AFSt4WKnv63N9XnEw5SIHUaL1dVl8ywvRBr8WrymdD14wIDAQAB
AoGAI5GJjDNnFEHIaDMfc3dN0rvAE7mQdv8LzPEEyNGJSMjtYJNlRZP8unLcJii7
6dmzXtI9uq2/JF7MbuMZpPkKlNcWX8knE9UFJIu1J1hkXBDeVViYDstwDk0OT624
J8B2ualRsSHBppgdhXEnXjR0vm2MX0k0UFbCLVG+4wrc+zECQQDpZG/Vc+rlwx8M
3z3fx0IeFG7MSeBI90savdDOwvdHsaYST2sLNsPsd525hi5GzXlv9EZAMJ24pQgF
200XZDOdAkEA0Mpv83ROsdRU6eOUOO35kFzQYl3iTyLF+GVqAKUzcqwyRI+rhoLU
8g+Gy7JhkJf5AGJU7BV0/xlRBhsbVYVXfwJAQFKr97ogzP3/ur50AQ6bjEq5Vpgt
ti5hhpc1yyY0nI+7Y2R77fVD/hHhaFYwvta2V0KNcfd0IIVrNqIAFyhIiQJAVUj7
pcRyiK0k6kzttLtwX4mqDSQwVwbrOuWiARV6CHNSLTNKay1x8lZpRzdcJwYMzh1c
dvrkyXb747Sa27oV3QJBAOLQpiwWSpkEYH9oj4Qv3CmGiZGbypYQz0hXtbaLmpYR
br1KyfVS5IlJTlMashRuyhl5CW1wU8WiQnSVvXmFwPg=
-----END RSA PRIVATE KEY-----'
    );

    public function __construct()
    {

        $this->_config = $this->rsa_config;
    }

    /**
     * 私钥加密
     */
    public function privateKeyEncode($data)
    {
        $encrypted = '';
        $this->_needKey(2);
        $private_key = openssl_pkey_get_private($this->_config['private_key']);
        $fstr = array();
        $array_data = $this->_splitEncode($data);
        foreach ($array_data as $value) {
            openssl_private_encrypt($value, $encrypted, $private_key);
            $fstr[] = $encrypted;
        }
        return base64_encode(serialize($fstr));
    }

    /**
     * 公钥加密
     */
    public function publicKeyEncode($data)
    {
        $encrypted = '';
        $this->_needKey(1);
        $public_key = openssl_pkey_get_public($this->_config['public_key']);
        $fstr = array();
        $array_data = $this->_splitEncode($data);
        foreach ($array_data as $value) {
            openssl_public_encrypt($value, $encrypted, $public_key);
            $fstr[] = $encrypted;
        }
        return base64_encode(serialize($fstr));
    }

    /**
     * 用公钥解密私钥加密内容
     */
    public function decodePrivateEncode($data)
    {
        $decrypted = '';
        $this->_needKey(1);
        $public_key = openssl_pkey_get_public($this->_config['public_key']);
        $array_data = $this->_toArray($data); //数据base64_decode 后 反序列化成数组
        $str = '';
        foreach ($array_data as $value) {
            openssl_public_decrypt($value, $decrypted, $public_key); //私钥加密的内容通过公钥可用解密出来
            $str .= $decrypted; //对数组中的每个元素解密 并拼接
        }
        return base64_decode($str); //把拼接的数据base64_decode 解密还原
    }

    /**
     * 用私钥解密公钥加密内容
     */
    public function decodePublicEncode($data)
    {
        $decrypted = '';
        $this->_needKey(2);
        $private_key = openssl_pkey_get_private($this->_config['private_key']);
        $array_data = $this->_toArray($data);
        $str = '';
        foreach ($array_data as $value) {
            openssl_private_decrypt($value, $decrypted, $private_key); //私钥解密
            $str .= $decrypted;
        }
        return base64_decode($str);
    }

    /**
     * 检查1 公钥 2 私钥
     */
    private function _needKey($type)
    {
        switch ($type) {
            case 1:
                if (empty($this->_config['public_key'])) {
                    throw new \Exception('请配置公钥');
                }
                break;
            case 2:
                if (empty($this->_config['private_key'])) {
                    throw new \Exception('请配置私钥');
                }
                break;
        }
        return 1;
    }

    /*
     * @param type $data
     */
    private function _splitEncode($data)
    {
        $data = base64_encode($data); //加上base_64 encode  便于用于 分组
        $total_lenth = strlen($data);
        $per = 96; // 能整除2 和 3 RSA每次加密不能超过100个
        $dy = $total_lenth % $per;
        $total_block = $dy ? ($total_lenth / $per) : ($total_lenth / $per - 1);
        for ($i = 0; $i < $total_block; $i++) {
            $return[] = substr($data, $i * $per, $per); //把要加密的信息base64 后 按64长分组
        }
        return $return;
    }

    /**
     * 公钥加密并用 base64 serialize 过的 data
     * @param type $data base64 serialize 过的 data
     */
    private function _toArray($data)
    {
        $data = base64_decode($data);
        $array_data = unserialize($data);
        if (!is_array($array_data)) {
            throw new \Exception('数据加密不符');
        }
        return $array_data;
    }

}
