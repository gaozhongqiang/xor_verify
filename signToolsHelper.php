<?php
/**
 * 获取请求数据进行sign校验
 * Created by PhpStorm.
 * User: 高忠强
 * Date: 2018/11/16
 * Time: 14:58
 * 参考邱的加密代码
 */
namespace app\Helpers;
use Illuminate\Support\Facades\Cache;
use App\Helpers\filterToolsHelper;

class signToolsHelper{
    //参数定义
    const InterfaceTimeKeyName = 'timeStamp';
    const InterfaceRandomKeyName = 'randomNum';
    const InterfaceTimeStampCacheTime = '180';
    const InterfaceRandomCacheTime = '3600';
    const EncryptString = 'fjsdklfjdslfkdsajflddasdsafdsfsafsfdsgfdgasdasdadasdasfsafdsfaad';

    public static function get_request_data($query_arr){
        if(empty($query_arr)) return array(-1,"请传递要进行验证的参数！");
        $auth_string=isset($_REQUEST["auth_string"]) ? $_REQUEST["auth_string"] : '';
        if(empty($auth_string)) return array(-1,"auth_string字符串有误！");

        list($errorno,$errormsg)=self::calculation_random_time_sign(array("auth_string"=>$auth_string));
        if(!empty($errorno)) return array($errorno,$errormsg);
        $query_string = self::encrypt_xor_value($auth_string,'dencode',self::EncryptString);
        parse_str($query_string,$source_arr);

        if(!is_array($source_arr)) return array(-210,"参数解析有误！");
        @list($errorno,$param_arr,$danger_arr)=self::decomposition_parameter($source_arr,$query_arr);
        if(!empty($errorno)) return array($errorno,$param_arr);
        return array($errorno,$param_arr,$danger_arr);
    }
    /***
     * 计算sign
     * $request_arr	接收到的参数，用作参数sign计算的参数。
     */
    private static function calculation_random_time_sign($request_arr){
        $sign_arr = array(
            self::InterfaceTimeKeyName	=>$_REQUEST[self::InterfaceTimeKeyName],
            self::InterfaceRandomKeyName=>$_REQUEST[self::InterfaceRandomKeyName]
        );
        if(empty($sign_arr[self::InterfaceTimeKeyName]) || empty($sign_arr[self::InterfaceRandomKeyName])){
            return array(-210,"随机参数或者时间参数信息不存在！");
        }
        if(mb_strlen($sign_arr[self::InterfaceTimeKeyName],"utf-8")<8){
            return array(-211,"随机参数信息数据大小不对！");
        }
        /*******************************************************************************************************************************
        表示是否需要在url地址中加入随机数（随机数缓存周期为一个小时也就是说重复的随机数一个小时只能出现一次）和时间戳（时间戳缓存3分钟）
         ********************************************************************************************************************************/
        if(time()-$sign_arr[self::InterfaceTimeKeyName]>self::InterfaceTimeStampCacheTime){
            return array(-208,"时间参数信息有误！");
        }
        $radom_cache_key = md5("random_".$sign_arr[self::InterfaceRandomKeyName]);
        $radom_cache = Cache::get($radom_cache_key);
        if(!empty($radom_cache)){
            return array(-209,"随机参数信息有误！");
        }
        Cache::put($radom_cache_key,$radom_cache_key,self::InterfaceRandomCacheTime);
        $arr = $sign_arr+$request_arr;
        ksort($arr);
        if($_REQUEST["sign"] != md5(self::http_build_query_noencode($arr))){
            return array(-205,"-205不正常链接！");
        }
        return array(0,"");
    }
    /********************************************************************************
    按位异或
    $value					需要进行加密或者解密的值
    $type						encode表示加密，decode表示解密
    $encryt_string	加密串
    ------------------------------------------------------------------------
    当前方法是对encryption_helper.php中的function encryp_xor_value函数进行修改得到。
     **********************************************************************************/
    private static function encrypt_xor_value($value,$type = 'encode',$encryt_string= ''){
        if(empty($value)) return '';
        return $type=="encode" ? self::base64url_encode(self::xor_encrypt_bit($value,$encryt_string)) : self::xor_encrypt_bit(self::base64url_decode($value),$encryt_string);
    }
    /************************************************************************
    将指定字符串与加密字符串中的字符按位进行异或处理。
    $value					要加密的字符串
    $encryt_string	加密串
     ***************************************************************************/
    private static function xor_encrypt_bit($value,$encryt_string = ''){
        for($i=0,$v="";$i<strlen($value);$i++){
            $v.=$value{$i} ^ $encryt_string{$i%strlen($encryt_string)};
        }
        return $v;
    }
    /******************************************************************************
    将base64_encode后的字符串将加号和斜杠替换成中划线和下划线。
    strtr的使用方法（1按顺序替换，2不会影响原来字符串）：
    $str="alonesdfsdf+sdfsdfsdf/sdfadf";
    $str2=strtr($str,"+/","-_");
    print_r($str);	//alonesdfsdf+sdfsdfsdf/sdfadf
    print_r($str2);	//alonesdfsdf-sdfsdfsdf_sdfadf
    来自PHP文档：base64_encode
    -----------------------The Author Of ALone 2017-08-04 10:27
     *********************************************************************************/
    private static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    /*****************************************************************************************************************
    首先strtr($data, '-_', '+/')将-_替换成+/，
    string str_pad ( string $input , int $pad_length [, string $pad_string = " " [, int $pad_type = STR_PAD_RIGHT ]] )
    参数：
    如果 pad_length 的值是负数，小于或者等于输入字符串的长度，不会发生任何填充，并会返回 input
    下面是首先给$data将-_替换为+/，接着给加密串后面补上=号。
     *****************************************************************************************************************/
    private static function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), (strlen($data) % 4)+strlen($data), '=', STR_PAD_RIGHT));
    }
    /******************************************************************************************
    分解过滤参数
    $source_arr		需要进行分解的参数。
    $query_arr		需要接收的参数列表
    -------------------------------------------------The Author Of ALone 2017-08-02 18:46
    返回值：
    $param_arr		安全数据
    $danger_arr		危险数据
    当前函数是对sign_helper.php文件中的function DecompositionParameter修改得到。
    -------------------------------------------------The Author Of ALone 2018-02-26 18:02
     *******************************************************************************************/
    private static function decomposition_parameter($source_arr,$query_arr){
        $param_arr=$danger_arr=array();
        foreach($query_arr as $key => $value){
            if(!isset($source_arr[$key])){
                return array(-203,isset($value["EmptyError"]) ? $value["EmptyError"] : "-203提交的参数有误！");
            }
            $param_arr[$value["KeyName"]]=$danger_arr[$value["KeyName"]]=$source_arr[$key];
            $param_arr[$value["KeyName"]]=empty($value["IsNumber"]) ? trim($param_arr[$value["KeyName"]]) : $param_arr[$value["KeyName"]];
            /*****************************************************************************************************************************
            非空判断，要首先注意当前字段类型是字符串类型还是数值类型，如果是字符串类型就算传递0也算是空。如果是数值类型传递0不算是空的。
            所以这里处理是为了防止数值类型的参数用户传递0被当成空处理了。
             ******************************************************************************************************************************/
            if(!empty($value["NotEmpty"]) && empty($param_arr[$value["KeyName"]]) && empty($value["IsNumber"])){
                return array(-203,isset($value["EmptyError"]) ? $value["EmptyError"] : "-203提交的字符串类型参数有误！");
            }
            if(!empty($value["NotEmpty"]) && empty($param_arr[$value["KeyName"]]) && !empty($value["IsNumber"]) && !is_numeric($param_arr[$value["KeyName"]])){
                return array(-203,isset($value["EmptyError"]) ? $value["EmptyError"] : "-203提交的数值类型参数有误！");
            }
            if(!is_numeric($param_arr[$value["KeyName"]]) && !empty($value["IsNumber"])){
                return array(-203,"-203{$key}参数类型不正确！");
            }
            $number_filter_function=isset($value["NumberFilter"]) ? $value["NumberFilter"] : "intval";
            $param_arr[$value["KeyName"]]=!empty($value["IsNumber"]) ? $number_filter_function($param_arr[$value["KeyName"]]) : filterToolsHelper::string($param_arr[$value["KeyName"]]);
        }
        return array(0,$param_arr,$danger_arr);
    }
    /***************************************************************************************
    $queryArr			要进行处理的数组数据
    $unset_empty	判断是否如果为空的时候就不加入querystring
    $is_sort			是否是正序排序-------------------------------2018-03-01 10:59 由ALone添加。
    $delimiter		分隔符
    当前方法是对uri_helper.php文件中的function http_build_query_noencode_upgrade修改得到。
     ****************************************************************************************/
    public static function http_build_query_noencode($query_arr,$unset_empty=-1,$is_sort=-1,$delimiter="&"){
        if(empty($query_arr)){
            return "";
        }
        $is_sort==1 && ksort($query_arr,SORT_STRING);
        $return_arr=array();
        array_walk($query_arr,function ($value,$item) use (&$return_arr,$unset_empty){
            $return_arr[$item]="{$item}={$value}";
            if($unset_empty==1){
                if(empty($value) && !is_numeric($value)) unset($return_arr[$item]);
            }
        });
        return !empty($return_arr) ? implode($delimiter,$return_arr) : "";
    }
}