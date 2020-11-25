# Tuto OAuth

## Description
This repository is the code for learning how to set up OAuth2 for authentication with github
## Set up the App

    $ composer install
	
	## database setup create .env.local conforming with .env
	$ php bin/console doctrine:database:create  
	$ php bin/console doctrine:migrations:migrate
    
	## run app
	$ php -S localhost:8000 -t public