General db safety 

You can't prevent an attacker to compomise your db with db design. You can (and should) limit how much damage a compromised app can cause.  

How to limit blast radius
    (1) Threat

    We assue: 
        - The web server CAN be compromised; 
        - PHP (or any backend language) CAN be modified or abused; 
        - Attackers CAN gain the same privileges as the PHP (backend) script. 
    
    (2) Core concepts: 
     - Give the minimun level possible of privilage to your script (!!)

        *BAD pattern: 
            - One db user used everywhere; 
            - Full privileges.
        
        PHP script compromized --> db compromized --> everything lost

        *GOOD pattern: 
            - One db; 
            - Multiple users; 
            -Each user with MINIMAL permissions. 
    
    (3) Db roles mapped to app responsibilities
        Think it in terms of what each script is allowed to do. 

        e.g. 
        Role name    | Purpose           | Permissions                   |
        _____________|___________________|_______________________________|
        app_register | Create user       | INSERT on users               |
        _____________|___________________|_______________________________|
        app_login    | Auth users        | SELECT password_hash          |
        _____________|___________________|_______________________________|
        app_readonly | UI display        | SELECT limited columns        |
        _____________|___________________|_______________________________|
        app_writer   | Normal app actions| INSERT/UPDATE specific tables |
        _____________|___________________|_______________________________|
        app_admin    | Maintenance       | Rare, manual use              |
        _____________|___________________|_______________________________|
            