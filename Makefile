all:
	@cp signingFunctions.py Client1/signingFunctions.py
	@cp socketFunctions.py Client1/socketFunctions.py
	
	@cp -r Client1/ Client2/
	
	@cp signingFunctions.py Server/signingFunctions.py
	@cp socketFunctions.py Server/socketFunctions.py

clean:
	@rm -rf Client2/

	@rm -f Client1/signingFunctions.py
	@rm -f Client1/socketFunctions.py

	@rm -f Server/signingFunctions.py
	@rm -f Server/socketFunctions.py