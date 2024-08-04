#Author: Daniel Morales
#Version: 1.0

#Import section
from os import system
import pyfiglet
from colorama import Fore, Style

#Class
class Styles:

    def __init__(self,text):
        self.banner=text

    def ascii_banner(self):
        try:
            banner = pyfiglet.figlet_format(self.banner)
            system("clear")
            print(banner)
        except RuntimeError as e:
            print(e)

    def color_print(self,text,color):
        try:
            color_value = getattr(Fore, color.upper())
            print(Style.BRIGHT + color_value + text)
            print(Style.RESET_ALL)
        except AttributeError as e:
            print(e)


