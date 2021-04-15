package main

filecoin地址生成过程

//通过助记词得到种子
val seed = DeterministicSeed(
mnemonicCodes,
NumericUtil.toSeed(mnemonicCodes, ""),
"",
creationTimeSeconds
)

//通过biP44得到path
val path: String? = getPath(0)

//主密钥
val keyChain = DeterministicKeyChain.builder().seed(seed).build()
var rootPublicKey = keyChain.rootKey?.publicKeyAsHex
Log.d(TAG, "主公钥：$rootPublicKey")
val parent =
keyChain.getKeyByPath(BIP44Util.generatePath(path), true)
var p = Blake2b.Param()
p.digestLength = 20

//子私钥
var xprv = parent.privateKeyAsHex


Log.d(TAG, "子私钥：$xprv")
Log.d(TAG, "子私钥(Base58)：" + Base58.encode(parent.privKeyBytes))

//
val ecKey: ECKey =
ECKey.fromPrivate(NumericUtil.hexToBytes(xprv), false)

/**
 * 什么是压缩公钥？
 *
 * 什么是未压缩公钥？
 */

//未压缩公钥16进制
var pulStr =
	ecKey.publicKeyAsHex
Log.d(TAG, "未压缩公钥：$pulStr")

//未压缩公钥字节
val encryptionKey =
NumericUtil.hexToBytes(pulStr)

//将公钥前加入0x04值后，进行20位的blake2b计算
p.digestLength = 20
var blake2Hash = Blake2b.Digest.newInstance(p)
var blake2HashHexByte = blake2Hash.digest(encryptionKey)
var blake2HashHexStr = NumericUtil.bytesToHex(blake2HashHexByte)

Log.d(TAG, blake2HashHexStr)

//将得到的blake2哈希值前添加0x01后，继续用blake2b算法计算4位校验和
var blake2HashSecond = "01$blake2HashHexStr"

//用blake2b算法计算4位校验和
p.digestLength = 4
var blake2b3 = Blake2b.Digest.newInstance(p)
var checksumBytes = blake2b3.digest(NumericUtil.hexToBytes(blake2HashSecond))
var checksum =
	NumericUtil.bytesToHex(checksumBytes)
Log.d(TAG, "校检和：$checksum")

//将20位公钥哈希值和4位校验和连接起来
val addressBytes = ByteArray(blake2HashHexByte.size + checksumBytes.size)
System.arraycopy(blake2HashHexByte, 0, addressBytes, 0, blake2HashHexByte.size)
System.arraycopy(checksumBytes, 0, addressBytes, blake2HashHexByte.size, checksumBytes.size)
var address = "t1" + Base32New.encode(addressBytes)
Log.d(TAG, "地址：$address")
}

//m/44'/461'/0/0/0
private fun getPath(index: Int): String? {
//146或1
return "m/44'/461'/$index/0/0"
}