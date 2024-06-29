import pyttsx3
from multiprocessing import Process
import keyboard
engine = pyttsx3.init() #创建对象

def tts(word:str):
    print(word)
    engine.say(word)
    engine.runAndWait()

def duwen(wordlist:list):
    for word in wordlist:
        tts(word=word)
def Constant_say(phrase):
    duwen(phrase)

def say(phrase):
    print(__name__)
    if __name__ == "duwen":
        p = Process(target=duwen, args=(phrase,))
        p.start()
        while p.is_alive():
            # try:
            #     keyboard.wait('ctrl+c')
            #     p.terminate()
            # except KeyboardInterrupt:
            #     print('1')
            if keyboard.is_pressed('alt') and keyboard.is_pressed('c'):
                p.terminate()
            else:
                continue
        p.join()


