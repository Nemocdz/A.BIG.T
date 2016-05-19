//
//  TCPSSConnector.swift
//  SimpleTunnel
//
//  Created by 孔祥波 on 15/10/27.
//  Copyright © 2015年 Apple Inc. All rights reserved.
//

import Foundation



func settingSS(passwd:String,method:String) ->Int32 {
    if SFSettingModule.setting.method == -1 {
        
        let md = passwd.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        let mm = method.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        guard let pptr = md, mptr = mm else { return -1}
       
        //let pptr : UnsafeMutablePointer<Int8> = UnsafeMutablePointer.init(passwd.cStringUsingEncoding(NSUTF8StringEncoding)!)
        //let mptr : UnsafeMutablePointer<Int8> = UnsafeMutablePointer.init(method.cStringUsingEncoding(NSUTF8StringEncoding)!)
       
        //guard let pd = md, xd = mm else { return -1}
        SFSettingModule.setting.method = enc_init(UnsafePointer(pptr.bytes), UnsafePointer(mptr.bytes),pptr.length,mptr.length  )
    }
    return SFSettingModule.setting.method
    
}
public class  TCPSSConnector:ProxyConnector{
    //config_encryption(password, method);
    var decrypt_ctx:SEContextRef =  SEContextRef.alloc(1)//enc_ctx_create()//
    var encrypt_ctx:SEContextRef =  SEContextRef.alloc(1)//enc_ctx_create()//
    //leaks 
    let sbuf:bufferRef = bufferRef.alloc(1)
    let rbuf:bufferRef = bufferRef.alloc(1)
    //var
    var headSent:Bool = false
    //var auth:Bool = false
    func config() -> Bool{
        
//        decrypt_ctx = enc_ctx_create()
//        encrypt_ctx = enc_ctx_create()
        let m = settingSS(proxy.password,method: proxy.method)
        if m == -1 {
            return false
        }
        enc_ctx_init(m, encrypt_ctx, 1);
        enc_ctx_init(m, decrypt_ctx, 0);
        if mode == .TCP {
            balloc(sbuf,Int(TCP_CLIENT_SOCKS_RECV_BUF_SIZE_UInt))
            balloc(rbuf,Int(TCP_CLIENT_SOCKS_RECV_BUF_SIZE_UInt))
        }else {
            balloc(sbuf,CLIENT_SOCKS_RECV_BUF_SIZE)
            balloc(rbuf,CLIENT_SOCKS_RECV_BUF_SIZE)
        }
        
//        if targetHost.characters.count > 0 {
//            buildHead()
//        }
        
        return true
    }
    deinit {
        
        //maybe crash
        bfree(sbuf)
        sbuf.dealloc(1)
        bfree(rbuf)
        rbuf.dealloc(1)
        free_enc_ctx(encrypt_ctx)
        free_enc_ctx(decrypt_ctx)
    }


    func buildHead() ->NSData {
        let header = NSMutableData()
        //NSLog("TCPSS %@:%d",targetHost,targetPort)
        //targetHost is ip or domain
        var addr_len = 0
        
//        let  buf:bufferRef = bufferRef.alloc(1)
//        balloc(buf,BUF_SIZE)
        let  request_atyp:SOCKS5HostType = validateIpAddr(targetHost)
        if  request_atyp  == .IPV4{
           
            header.write(SOCKS_IPV4)
            addr_len += 1
           //AxLogger.log("\(cIDString) target host use ip \(targetHost) ",level: .Debug)
            let i :UInt32 = inet_addr(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!)
            header.write(i)
            header.write(targetPort.byteSwapped)
            addr_len  +=  sizeof(UInt32) + 2
            
        }else if request_atyp == .DOMAIN{
            
            header.write(SOCKS_DOMAIN)
            addr_len += 1
            let name_len = targetHost.characters.count
            header.write(UInt8(name_len))
            addr_len += 1
            header.write(targetHost)
            addr_len += name_len
            header.write(targetPort.byteSwapped)
            addr_len += 2
        }else {
            //ipv6
            header.write(SOCKS_IPV6)
            addr_len += 1
            if let data =  toIPv6Addr(targetHost) {
                
                
               //AxLogger.log("\(cIDString) convert \(targetHost) to Data:\(data)",level: .Info)
                header.write(data)
                header.write(targetPort.byteSwapped)
            }else {
               //AxLogger.log("\(cIDString) convert \(targetHost) to in6_addr error )",level: .Warning)
                //return
            }
            //2001:0b28:f23f:f005:0000:0000:0000:000a
//            let ptr:UnsafePointer<Int8> = UnsafePointer<Int8>.init(bitPattern: 32)
//            let host:UnsafeMutablePointer<Int8> = UnsafeMutablePointer.init(targetHost.cStringUsingEncoding(NSUTF8StringEncoding)!)
//            inet_pton(AF_INET6,ptr,host)
        }
        return header
//        buffer_t_copy(buf,UnsafePointer(header.bytes),header.length)
//        let len = buffer_t_len(buf)
//        if request_atyp == 1 && auth {
//            
//            if (!remote->direct) {
//                if (auth) {
//                    abuf->array[0] |= ONETIMEAUTH_FLAG;
//                    ss_onetimeauth(abuf, server->e_ctx->evp.iv, BUF_SIZE);
//                }
//                
//                brealloc(remote->buf, buf->len + abuf->len, BUF_SIZE);
//                memcpy(remote->buf->array, abuf->array, abuf->len);
//                remote->buf->len = buf->len + abuf->len;
//                
//                if (buf->len > 0) {
//                    if (auth) {
//                        ss_gen_hash(buf, &remote->counter, server->e_ctx, BUF_SIZE);
//                    }
//                    memcpy(remote->buf->array + abuf->len, buf->array, buf->len);
//                }
//            } else {
//                if (buf->len > 0) {
//                    memcpy(remote->buf->array, buf->array, buf->len);
//                    remote->buf->len = buf->len;
//                }
//            }
//            
//            
//           //one time auth
//           //AxLogger.log("\(cIDString) OTA enabled do s_onetimeauth \(header)",level: .Debug)
//            sss_onetimeauth(buf,encrypt_ctx,header.length)
//            
//            brealloc(sbuf, len + header.length, BUF_SIZE)
//            buffer_t_copy(sbuf,buffer_t_buffer(buf),len)
//            
//            let counter:UnsafeMutablePointer<UInt32> = UnsafeMutablePointer.init()
//            if len > 0 {
//                if (auth) {
//                    ss_gen_hash(buf, counter, encrypt_ctx, BUF_SIZE);
//                }
//                //memcpy(remote->buf->array + abuf->len, buf->array, buf->len);
//            }
//        }else {
//           //AxLogger.log("\(cIDString) OTA disabled",level: .Debug)
//            if len > 0 {
//                buffer_t_copy(sbuf,UnsafePointer(header.bytes),header.length)
//            }
//        }
//        bfree(buf)
//       //AxLogger.log("\(cIDString) ss connect head \(header)",level: .Debug)
        
    }
    
    public override func socket(sock: GCDAsyncSocket!, didConnectToHost host: String!, port: UInt16){
        
       let message = String.init(format: "\(targetHost):\(targetPort) UP \(host):\(port)")
        remoteIPaddress = host
        debugLog(message)
        if let d = delegate {
            d.connectorDidBecomeAvailable(self)
        }
        
        //        for (index ,packet) in packets.enumerate() {
        //           //AxLogger.log("writeData \(packet)")
        //            socket?.writeData(packet, withTimeout: 10, tag: 0)
        //            packets.removeAtIndex(index)
        //        }
    }
  
    public override func socket(sock: GCDAsyncSocket!, didReadData data: NSData!, withTag tag: Int) {
       //AxLogger.log("\(cIDString) didReadData \(data.length) \(tag)",level: .Trace)
        //receivedData = data
        //NSLog("TCSS read data len:%d",data.length)
        if data.length > 0 {
        
            //receivedData.appendData(data)
            //AxLogger.log("\(cIDString) buffer \(data)",level: .Trace)
//            let recvb:bufferRef = bufferRef.alloc(1)
//            balloc(recvb,receivedData.length)
            buffer_t_copy(rbuf,UnsafePointer(data.bytes),data.length)
            let ret = ss_decrypt(rbuf, decrypt_ctx,data.length)
            //let x = tag+1
            if ret != 0  {
               //AxLogger.log("\(cIDString) ss_decrypt error ",level: .Error)
                //self.readDataWithTimeout(0.1, length: 2048, tag: x)
            }else {
                let len = buffer_t_len(rbuf)
                let out = NSData.init(bytes: buffer_t_buffer(rbuf), length: len)
                //AxLogger.log("\(cIDString) decrypt \(out)",level: .Debug)
                if let d = delegate {
                     d.connector(self, didReadData: out, withTag: Int64(tag))
                }
               
            }
            
        }
        
        //socket?.readDataWithTimeout(0.5, tag: self.tag++)
    }
//    public override func socket(sock: GCDAsyncSocket!, didReadPartialDataOfLength partialLength: UInt, tag: Int){
//       //AxLogger.log("\(cIDString) didReadPartialDataOfLength",level: .Warning)
//        if let d = delegate {
//            d.connector(self, didReadData: self.receivedData, withTag: Int64( tag))
//        }
//        
//    }
    public override func socket(sock: GCDAsyncSocket!, didWriteDataWithTag tag: Int){
       //AxLogger.log("\(cIDString) didWriteDataWithTag   \(tag)",level:.Warning)
        //NSLog("TCPSS didwrite tag %d",tag )
        if let d = delegate {
            d.connector(self, didWriteDataWithTag: Int64(tag))
        }else {
            //NSLog("TCPSS delegate invalid %d",tag )
        }
        
    }
    public func beginRead(){
        socket?.readDataWithTimeout(socketReadTimeout, tag: 0)
    }
//    public override func readDataWithTimeout(timeout :Double ,length:UInt32,  tag  :CLong){
//        //        guard let buffer = self.receivedData else{
//        //           //AxLogger.log("read error withtag   \(tag) \(length)")
//        //            return;
//        //        }
//        //
//        //socket?.readDataToLength(length: length , timeout : timeout, tag: tag)
//        // socket?.readDataToLength(UInt( length), withTimeout: timeout, tag: CLong(tag))
//        
//        socket?.readDataWithTimeout(timeout, buffer: nil, bufferOffset: 0, maxLength: UInt(length) , tag: tag)
//        
//    }
    public func socket(sock: GCDAsyncSocket!, didWritePartialDataOfLength partialLength: UInt, tag: Int){
       //AxLogger.log("\(cIDString) didWritePartialDataOfLength \(partialLength) \(tag)",level:.Trace)
    }
//    public override func socket(sock: GCDAsyncSocket!, shouldTimeoutReadWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutReadWithTag ", level:.Warning)
//        return 10
//    }
//    public override func socket(sock: GCDAsyncSocket!, shouldTimeoutWriteWithTag tag: Int, elapsed: NSTimeInterval, bytesDone length: UInt) -> NSTimeInterval{
//       //AxLogger.log("\(cIDString) shouldTimeoutWriteWithTag ", level:.Warning)
//        return 10
//    }
    public func socketDidCloseReadStream(sock: GCDAsyncSocket!){
        
        let e = NSError(domain:errDomain , code: 0,userInfo:["reason":"socketDidCloseReadStream"])
       //AxLogger.log("\(cIDString) socketDidCloseReadStream \(e)", level:.Warning)
        if let d = delegate {
            //self.socket = nil
            d.connectorDidDisconnect(self, withError: e)
        }
        
        
    }
    public override func socketDidDisconnect(sock: GCDAsyncSocket!, withError err: NSError!){
       //AxLogger.log("\(cIDString) socketDidDisconnect,err: \(err)",level:  .Error)
        var e:NSError
        if let _ = err {
            e = NSError(domain:errDomain , code: err.code,userInfo: err.userInfo)
        }else{
            e = NSError(domain:errDomain , code: 0,userInfo: ["info":"debug"])
        }
        if let d = delegate {
            //self.socket = nil
            d.connectorDidDisconnect(self, withError: e)
        }
        
        
    }

    public override func start() {
        if proxy.tlsEnable {
            proxy.tlsEnable = false
           //AxLogger.log("\(cIDString) proxy config err,ss don't need tls",level:.Error)
        }
        super.start()
    }
    public func test_encryptor(buffer:NSData)  {
        //let tmp = NSData.init(data: buffer)
        
        print(buffer)
        let sendb:bufferRef = bufferRef.alloc(1)
        balloc(sendb,2048)
        buffer_t_copy(sendb,UnsafePointer(buffer.bytes),buffer.length)
        var ret = ss_encrypt(sendb,encrypt_ctx,buffer.length)
        if ret != 0 {
            //abort()
           //AxLogger.log("\(cIDString) ss_encrypt error ",level: .Error)
        }
        var  len = buffer_t_len(sendb)
        
        let recvb:bufferRef = bufferRef.alloc(1)
        balloc(recvb,2048)
        buffer_t_copy(recvb,buffer_t_buffer(sendb),len)
        ret = ss_decrypt(recvb,decrypt_ctx,len)
        if ret != 0 {
            //abort()
           //AxLogger.log("\(cIDString) ss_decrypt error ",level: .Error)
        }
        len = buffer_t_len(recvb)
        let out = NSData.init(bytesNoCopy:buffer_t_buffer(recvb) , length: len, freeWhenDone: false);
        print(out)
        sendb.dealloc(1)
        recvb.dealloc(1)
    }
    public override func writeData(d:NSData, timeout:Double, tag:Int64){
        //
        
        //AxLogger.log("writedata \(d)",level: .Trace)
        if isConnected() == true {
            
            //test_encryptor(buffer)
            
            if !headSent {
                let temp = NSMutableData()
                let head = buildHead()
                temp.appendData(head)
                temp.appendData(d)
                brealloc(sbuf,temp.length,CLIENT_SOCKS_RECV_BUF_SIZE)
                buffer_t_copy(sbuf,UnsafePointer(temp.bytes),temp.length)
                headSent = true
               //AxLogger.log("\(cIDString) will send \(head.length) \(head) ",level: .Trace)
            }else {
                brealloc(sbuf,d.length,d.length)
                buffer_t_copy(sbuf,UnsafePointer(d.bytes),d.length)
            }
           //AxLogger.log("\(cIDString) will send \(d.length)  ",level: .Trace)
            
            
            
            var  len = buffer_t_len(sbuf)
            let ret = ss_encrypt(sbuf,encrypt_ctx,len)
            if ret != 0 {
                //abort()
               //AxLogger.log("\(cIDString) ss_encrypt error ",level: .Error)
            }
            len = buffer_t_len(sbuf)
            let result = NSData.init(bytes: buffer_t_buffer(sbuf), length: len)

            socket?.writeData(result, withTimeout: timeout, tag: Int(tag))
        }else{
            //packets.append(d);
           //AxLogger.log("\(cIDString) packets.append",level:.Trace)
        }
        
    }
    
    static func connectorWithSelectorPolicy(selectorPolicy:SFPolicy ,targetHostname hostname:String, targetPort port:UInt16,p:SFProxy) ->TCPSSConnector{
        let c:TCPSSConnector = TCPSSConnector(spolicy: selectorPolicy, p: p)
        //c.manager = man
        //c.policy = selectorPolicy
        //TCPSSConnector.swift.[363]:12484608:12124160:360448:Bytes
        c.cIDFunc()
        c.targetHost = hostname
        c.targetPort = port
        
        //c.start()
        return c
    }

}

