from Crypto.Cipher import AES  
from base64 import b64decode, b64encode
from Crypto.Util.Padding import pad,unpad

import random
import requests
import json
import re
from PIL import Image
from io import BytesIO

from duwen import say,Constant_say
class AES_Cipher():
    def __init__(self,tempKey:str='',tempVi:str = '') -> None:
        self.__tempKey = b64decode(tempKey)
        self.__tempiv = b64decode(tempVi)

    def AES_CBC_decrypt(self,cipherText:bytes) ->str:#解密
        #b'56Tg0IL4zTG9iJ4kGAwlp3sefZQ0Nljty2mAtfnq5ys=' ->b'\xe3\x80\x80\xe3\x80\x80\xe2\x80\x9c\xe5\x97\xaf\xe3\x80\x82\xe2\x80\x9d'
        cipherText = b64decode(cipherText)#先将base64 编码 转换成byte类型
        decrypter=AES.new(self.__tempKey ,AES.MODE_CBC,iv=self.__tempiv)#设置好 key cbc iv
        plaintext = decrypter.decrypt(cipherText)#解密
        unpadtext=unpad(plaintext,16,'pkcs7')#去除填充
        return unpadtext.decode('utf-8')
        
    def AES_CBC_encrypt(self,text:bytes) ->bytes:#加密
        if isinstance(text,str):
            text = bytes(text,encoding="utf-8")
        cipher=AES.new(self.__tempKey ,AES.MODE_CBC,iv=self.__tempiv)
        padtext=pad(text,16,style='pkcs7')
        cipherText=cipher.encrypt(padtext)
        return b64encode(cipherText)


# A = AES_Cipher('N2FlYTA0YjA3MTVjOGVjNThhODU3Y2U5ZTJiYzZmZmQ=','OTYzNmUxNjE4ZTdjN2Y4MA==')
# cipherText = A.AES_CBC_encrypt('　　“嗯。”')
# print(A.AES_CBC_decrypt(cipherText))
class ShaoNianMeng():
    __header  = {
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'zh-CN,zh;q=0.9',
        'origin': 'https://www.shaoniandream.com',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',   
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        'x-requested-with': 'XMLHttpRequest',
    }
    __cookies = {
        'Hm_lvt_79e51ba08bd734f72224ccd0de30c8b0': '1718939089',
        'PHPSESSID': 'esc2vcj5rn6ak98s3gf9qnas79',
    }
    def random16str(self,p:int=0):
        #生成一个长度为 0 后面有16位小数的随机数
        a = random.uniform(0, 1)
        #这个随机数命名我是没想到的2024/6/29 18.00
        if p:
            return {'randomm':str(round(a,16))}
        return {'randoom':str(round(a,16))}#一步到位 直接返回dict

    
    def getchapter(self,chapterid:int=0):
        url = 'https://www.shaoniandream.com/booklibrary/membersinglechaptersign/chapter_id/{}'.format(chapterid)
        params = self.random16str()
        header = self.__header
        header['referer'] = 'https://www.shaoniandream.com/readchapter/{}'.format(chapterid)
        r = requests.post(url=url,params=params,cookies=self.__cookies,headers=header)
        alist = []
        if r.status_code == 200:
            #先相信这个网站不会封我
            temp = json.loads(r.text)
            # print(type(temp['status']),temp['status'] != 1)
            if temp['status'] != 1:
                print(temp)
                return []
            data = {
                'chapter_access_key': temp['data']['chapter_access_key'],
                'isMarket': '1',
            }
            params = self.random16str(1)
            header['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            url = 'https://www.shaoniandream.com/booklibrary/membersinglechapter/chapter_id/{}'.format(chapterid)
            r1 = requests.post(url=url,params=params,cookies=self.__cookies,headers=header,data=data)
            temp1 = json.loads(r1.text)
            chapterpic = temp1['data']['chapterpic']
    
            if len(chapterpic) > 0:
                self.openimg(chapterpic)
            A = AES_Cipher(temp1['data']['encryt_keys'][0],temp1['data']['encryt_keys'][1])
            for i in temp1['data']['show_content']:
                i:dict
                alist.append(re.sub(r'\s', ' ',A.AES_CBC_decrypt(i['content']) ))
        else:
            pass
        return alist
    
    def openimg(self,imglist:list):
        urlheaders = 'https://alioss.shaoniandream.com'
        for i in imglist:
            i:dict
            url = urlheaders+i['url']
            r = requests.get(url=url,headers=self.__header)
            tempIm = BytesIO(r.content)
            im = Image.open(tempIm)
            im.show(i['miaoshu'])
            

    def getbookdetaildir(self,bookid:int):
        data = {
            'BookID':str(bookid)
        }
        r = requests.post('https://www.shaoniandream.com/booklibrary/getbookdetaildir',cookies=self.__cookies,headers=self.__header,data=data)
        temp = json.loads(r.text)

        booklist = temp['data']['readdir'][0]['list']
        return list(booklist)

B = ShaoNianMeng()
# chapterlist = B.getbookdetaildir(3569)
# print([i['id'] for i in chapterlist])
'''
[219452, 219454, 219660, 219882, 220098, 220232, 220294, 220504, 220505, 220673, 220674, 220900, 220901, 221119, 
221120, 221314, 221315, 221546, 221548, 221758, 221761, 221763, 222012, 222016, 222210, 222211, 222442, 222443, 
222642, 222644, 222871, 222872, 223065, 223068, 223283, 223284, 223505, 223506, 223684, 223687, 223888, 223890, 
223891, 224106, 224108, 224109, 224110, 224112, 224324, 224326, 224532, 224534, 224779, 224780, 224986, 224987,
225199, 225200, 225385, 225386, 225611, 225613, 225815, 225816, 225925, 225954, 225955, 226182, 226183, 226342,
226343]
'''
# for i in chapterlist:
#     print(i['id'])
# wordlist = B.getchapter(219454)
# with open('./pp.txt','w',encoding = 'utf-8') as f:
#     for i in wordlist:
#         # print(i)
#         f.write(i+'\n')
if __name__ == "__main__":
    wordlist = B.getchapter(223890)
    # say(wordlist)
    Constant_say(wordlist)

