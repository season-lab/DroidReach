import sys

from apk_analyzer import APKAnalyzer

def usage():
    print("USAGE: %s <apk>" % sys.argv[0])

if __name__ == "__main__":
    apka = APKAnalyzer()
