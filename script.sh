#!/bin/bash
echo Starting my app.
cd  /home/ubuntu/Sesion19CP/Sesion19CP
gunicorn -b 0.0.0.0:443 --certfile=micertificado.cer --keyfile=llaveprivada.pem wsgi:app
