#!/usr/bin/python
from socket import socket, SOCK_STREAM, AF_INET
from sys import argv

class Connection:

    def __init__(self) -> None:
        self.__socket = socket(AF_INET, SOCK_STREAM)
        self.__connected: bool = False
    
    def connect(self, host: str, port: int):
        try:
            self.__socket.connect((host,port))
            self.__connected =  True
        except:
            self.__connected =  False
        return self.__connected

    def disconnect(self):
        if self.__socket:
            self.__socket.close()
        self.__connected = False

    def write(self, data: str):
        if self.__connected:
            data = str(data).encode()
            return self.__socket.send(data)
        return -1
    
    def read(self):
        data = b''
        if self.__connected:
            rcv = 1
            while rcv:
                rcv = self.__socket.recv(2048)
                data += rcv
        return data.decode(encoding = "ISO-8859-1")
                

class Resolution:

    def __init__(self, authority: str, domain: str) -> None:
       self.__authority: str = authority
       self.__domain: str = domain
       self.__port: int = 43
  
    def resolver(self):
        data = f"{self.__domain}\n\r"
        self.connection = Connection()
        self.connection.connect(self.__authority, self.__port)
        self.connection.write(data)
        return self.connection.read()
         

class Format:

    def __init__(self, data: str) -> None:
        if data:
            self.__data = data.split("\n")
        else:
            self.__data = []
        
    def data(self)->tuple:
        copy = self.__data.copy()
        for value in self.__data:
            if value == '' or value[0] == '%':
                copy.remove(value)
            else:
                copy.remove(value)
                value = value.strip()
                copy.append(value)
        return tuple(copy)


class IANA(Format):
    
    def __init__(self, data: str):
        super().__init__(data)
        self.__refer = self.__get_refer()
    
    def __get_refer(self):
        for data in self.data():
            return data.split(":")[1].strip()
        return ''

    def refer(self)-> str:
        return self.__refer


class NIR(Format):
    def __init__(self, data: str):
        super().__init__(data)


class Whois:
    
    def __init__(self) -> None:
        self.__iana_host: str = "whois.iana.org"
        self.__iana: IANA = None
        self.__nir: NIR = None

    def question(self, domain: str):
        resolution = Resolution(self.__iana_host, domain)
        data: str = resolution.resolver()
        self.__iana = IANA(data)
        
        resolution = Resolution(self.__iana.refer(), domain)
        data: str = resolution.resolver()
        self.__nir = NIR(data)

    def iana(self)-> IANA:
        return self.__iana

    def nir(self)-> NIR:
        return self.__nir


def show():
    print()
    print('*************************************************** Py Whois ***************************************************                                        ')
    
    if argv.__len__() == 1:
        print("Entre com um dominio ou um endereço IP.")
    else:
        who = Whois()
        who.question(argv[1])
        format(who)

def get_data_format(reference, data):
    if data.__len__() > 0:
        print()
        print(f'                                                    ------> {reference} <------')
        print()
        for value in data:
            print(value)

def format(who):
    get_data_format("IANA",who.iana().data())
    get_data_format("NIR", who.nir().data())    
    print()

def main():
    show()
    
    
if __name__ == "__main__":
    main()