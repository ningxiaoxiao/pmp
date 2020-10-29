# -*- coding: utf-8 -*-
import requests
import hashlib
from Crypto.Cipher import AES
import json
import base64
import re
from threading import Thread
import os
import io
import sys
import shutil
import m3u8
from urllib.parse import urljoin

# sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8')
# sys.stdout=io.TextIOWrapper(encoding='utf8')


class M3u8Downloader():
    def __init__(self, m3u8_str, name, download_path, t_num, aes):

        self.aes = aes
        self.name = name
        self.download_path = download_path
        self.t_num = t_num
        self.save_path = os.path.join(self.download_path, "temp")
        self.txt_path = os.path.abspath(
            os.path.join(self.save_path, 'file.txt'))
        self.outfile = os.path.abspath(os.path.join(
            self.save_path, self.name))  # tmp下输出文件
        self.f_outfile = os.path.abspath(os.path.join(
            self.download_path, self.name))  # 最终路径文件

        m3u8_obj = m3u8.loads(m3u8_str)
        base_uri = m3u8_obj.base_uri
        self.url_list = [urljoin(base_uri, i) for i in m3u8_obj.files]
        del self.url_list[0]  # 去掉key文件
        self.now_p = 0
        self.all_p = len(self.url_list)

    def download(self):

        if os.path.exists(self.f_outfile):
            print('文件已经存在，跳过！')
            return

        if not os.path.exists(self.download_path):
            os.makedirs(self.download_path)

        if not os.path.exists(self.save_path):
            os.makedirs(self.save_path)

        with open(self.txt_path, 'w', encoding='utf8') as f:
            for index in range(len(self.url_list)):
                f.write("file " + os.path.abspath(self.save_path +
                                                  os.sep+f'{index}.ts').replace("\\", "\\\\")+"\n")

        tmpt_list = []
        allt_list = []
        for index, url in enumerate(self.url_list):

            t_in = Thread(target=self.download_, args=(index, url))
            t_in.start()
            tmpt_list.append(t_in)
            allt_list.append(t_in)

            if len(tmpt_list) == self.t_num:
                for t_out in tmpt_list:
                    t_out.join()
                tmpt_list = []

        # 等待全部完成
        for t_out in allt_list:
            t_out.join()
        print("下载完成!")
        self.hecheng()

    def download_(self, index, url):
        data = requests.get(url, stream=True).content
        data = self.aes.decrypt(data)
        with open(os.path.join(self.save_path, str(index)+".ts"), 'wb') as f:
            f.write(data)
        self.now_p += 1
        # print(str(round(self.now_p/self.all_p*100,2))+'%')

    def hecheng(self):
        sh = f'ffmpeg -f concat -safe 0 -i "{self.txt_path}" -c copy "{self.outfile}" -loglevel error'
        os.system(sh)
        shutil.move(self.outfile, self.f_outfile)
        shutil.rmtree(self.save_path)
        print("合并完成")


def down(url, filename):
    """
    docstring
    """
    key_data = requests.get(url).content
    print(key_data)
    with open(filename, 'wb') as f:
        f.write(key_data)


# down('https://hls.videocc.net/playsafe/060fd1513e/5/060fd1513e2d5c97b4317a896b370615_2.key?token=e19df84b-66af-41cc-abc5-080b1f8ad13f-x20032863','a.key')
# down('https://hls.videocc.net/060fd1513e/5/060fd1513e2d5c97b4317a896b370615_2.m3u8?pid=1603899080564X1505992&device=desktop','a.m3u8')
# down('https://player.polyv.net/secure/060fd1513e2d5c97b4317a896b370615_0.json','a.json')
I = bytes([2, 4, 6, 10, 14, 22, 26, 34, 38, 46, 58, 14, 10, 6, 4, 2])


def decode_json(vid: str, json_str: str):
    j = json.loads(json_str)['body']

    md5 = hashlib.md5()
    md5.update(vid.encode('utf-8'))
    vid_md5 = md5.hexdigest()
    a = vid_md5[16:]
    b = vid_md5[:16]

    c = AES.new(b.encode('utf8'), AES.MODE_CBC, a.encode('utf8'))
    json_bytes = bytes.fromhex(j)
    true_json = c.decrypt(json_bytes)
    true_json = base64.b64decode(true_json)
    j = json.loads(true_json)
    s_c = j['seed_const']

    videoname = j['title']+'.mp4'
    # print('sc is:',s_c)
    md5 = hashlib.md5()
    md5.update(str(s_c).encode('utf-8'))
    return md5.hexdigest(), videoname


def mod2(data):
    ret = bytes()
    for x in data:
        ret += (bytes([int(x/2)]))
    return ret


def print_bytes(data):
    """
    docstring
    """
    strs = ""
    for x in data:
        strs += str(x)+","
    print(strs)


def hex_decode(s: str):
    out = bytes()
    for x in s:
        out += (bytes([ord(x)]))
    return out


filedata = {}


def download_one(url, index, aes):
    data = aes.decrypt(requests.get(url).content)
    filedata[index] = data


def download(m3u8str, filename, key):
    res = re.compile('IV=0x(.*)').findall(m3u8str)
    if len(res) == 0:
        print("err:can not get IV", filename)
        return

    iv = res[0]  # 获取iv值

    cryptor = AES.new(key, AES.MODE_CBC, mod2(bytes.fromhex(iv)))

    m = M3u8Downloader(m3u8str, filename, 'video', 10, cryptor)
    m.download()

    # with open(filename,'ab') as f:
    #     for url in urls:
    #         f.write(cryptor.decrypt(requests.get(url).content))

# seed_const_md5=decode_json(json.loads(open('a.json',encoding='utf-8').read())['body'])

# hexstr=hex_decode(seed_const_md5[:16])

# key_data=open('a.key','rb').read()

# decode_key=AES.new(hexstr,AES.MODE_CBC,mod2(I))
# ture_key=decode_key.decrypt(key_data)[:16]


# download(m3u8_res,videoname,ture_key)

http_header = {"content-type": "application/x-www-form-urlencoded",
               "cookie": "JESONG_USER_ID=01000000013264033617572623486454; _rme=T; uname=%u5B81%u6F47%u6F47; _sid_=3f9dc8bfc132573bf7c73161736f48a7; Hm_lvt_555d9dcffdcb317595de82b0fc125cdf=1603268928,1603864960,1603953084; fromUrl=https%3A%2F%2Fwww.educity.cn%2F; cstk=024974edbdfc06a7c2457f79504ac8cd; _subjectCode_=100110021006; Hm_lpvt_555d9dcffdcb317595de82b0fc125cdf=1603956300"
               }


def get_video_list(tcid):
    url = "https://www.educity.cn/api/course/videoCourse/loadTree.do"
    html = requests.post(url, headers=http_header, data={"tcId": tcid}).content
    html_j = json.loads(html)
    return html_j['model']


def getPolyvToken(vid):
    url = "https://www.educity.cn/api/course/videoCourse/getPolyvToken.do"
    html = requests.post(url, headers=http_header, data={"vid": vid}).content
    return json.loads(html)['model']['token']


def loadbypk_get_url(pk):
    url = "https://www.educity.cn/api/course/videoCourse/loadByPK.do"
    html = requests.post(url, headers=http_header, data={"pk": pk}).content
    return json.loads(html)['model']['videoUrl']


def get_children_video(data):
    ret = []
    for vc in data['children']:
        vid = 0
        if 'videoId' in vc:
            vid = vc['videoId']
        elif 'videoID' in vc:
            vid = vc['videoID']
        if vid != 0:
            ret.append(vid)
        else:
            if 'children' in vc:
                return get_children_video(vc)
    return ret


def downloadByVid(videoId, hd='2'):
    video_url = loadbypk_get_url(videoId)

    print('videoId:', videoId)
    print('video_url:', video_url)

    token = getPolyvToken(video_url)

    print('token:', token)

    body_josn = requests.get(
        "https://player.polyv.net/secure/"+video_url+".json").text
    md5key, filename = decode_json(video_url, body_josn)
    hexstr = hex_decode(md5key[:16])

    print('filename:', filename)

    m3u8_str = requests.get(
        "https://hls.videocc.net/060fd1513e/9/"+video_url[:-1]+hd+".m3u8").text
    key_data = requests.get("https://hls.videocc.net/playsafe/060fd1513e/9/" +
                            video_url[:-1]+hd+".key?token="+token).content

    decode_key = AES.new(hexstr, AES.MODE_CBC, mod2(I))

    ture_key = decode_key.decrypt(key_data)[:16]

    print('key:', ture_key)
    if ture_key!=b'':
        download(m3u8_str, filename, ture_key)
    else:
        downloadByVid(videoId,'1')
    print('=======================end==========================')


def main(clss_id):
    videolist = get_video_list(clss_id)
    # print(videolist)
    video_id_list = []

    for v in videolist:
        video_id_list += get_children_video(v)

    print(video_id_list)
    for videoId in video_id_list:
        downloadByVid(videoId)

# downloadByVid('34035968','1')


# main('413060')20414543   412134
main('411633')
