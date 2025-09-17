# Shai-Hulud Checker
Shai-Hulud Checker


python3 main.py /ruta/al/proyecto


/home/user/scripts/check_shai_hulud.py
/home/user/app-node/package.json
/home/user/app-node/node_modules/


package.json
package-lock.json
yarn.lock
npm-shrinkwrap.json
node_modules/

Usage 
curl -sSf https://example.com/package.json | jq '.dependencies, .devDependencies'


# Escanear el proyecto actual
python3 main.py .

# Escanear otra carpeta
python3 main.py /var/www/proyecto --verbose

# Guardar reporte con otro nombre
python3 main.py /var/www/proyecto -o resultado.json