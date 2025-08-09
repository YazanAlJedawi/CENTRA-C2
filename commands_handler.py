import os

SCRIPT_NAME = os.path.basename(__file__)

AVALIABLE_EXECUTION_COMMANDS = ['list','listen','select','help','exit','logo']

LOGO_STR = r"""

 ██████╗███████╗███╗  ██╗████████╗██████╗  █████╗  ██████╗    ██████╗
██╔════╝██╔════╝████╗ ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝    ╚════██╗
██║     █████╗  ██╔██╗██║   ██║   ██████╔╝███████║██║          █████╔╝
██║     ██╔══╝  ██║╚████║   ██║   ██╔══██╗██╔══██║██║         ██╔═══╝ 
╚██████╗███████╗██║ ╚███║   ██║   ██║  ██║██║  ██║╚██████╗    ███████╗
 ╚═════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚══════╝

"""

def print_logo():
    print(LOGO_STR)

def entro():
    
    entro_msg = f"""\n
            -------------------------------------------------------------------------------------
           | CentraC2 Server is a very simple reverse shell handler combined with CentraC2 client. |
            -------------------------------------------------------------------------------------   
    
    {LOGO_STR}


    [+] Made By:     YazanAlJedawi: https://github.com/YazanAlJedawi 
    
    
      
        
    
"""                                                                                               
    return entro_msg

def help_msg_func():
    help_msg=f"""\n

    [+] How to use:

    [*] The server`s shell "turtle" is configured with a few commands that you can make use of:
    
    help:      prints this message.
    
    list:      lists all active connections to the server, each client with it`s ID.
    
    select:    supply it with the ID of the client of choice <<use list command to optain the ID>>
                and you shall have access to the client terminal.

    listen:    this triggers the listening functionality to turn the server up for clients.        

    logo:      prints the logo.

    exit:      shutdown the server.


    [*] Note: you can use the select command to switch to another client while you are accessing one.
    


"""
    return help_msg

def interface():
    inter = f"""\n
            -------------------------------------------------------------------------------------
           | CentraC2 Server is a very simple reverse shell handler combined with CentraC2 client. |
            -------------------------------------------------------------------------------------   
    
    {LOGO_STR}


    [+] Made By:     YazanAlJedawi: https://github.com/YazanAlJedawi 
    
    
"""                   
    return inter
