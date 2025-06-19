#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validador de RUT Chileno
Sistema de Control de Acceso SKYN3T
"""

import re
import sys

class RutValidator:
    """Clase para validar RUT chilenos"""
    
    @staticmethod
    def clean_rut(rut):
        """
        Limpia el RUT de caracteres no deseados
        Acepta formatos: 12.345.678-K, 12345678K, 12345678-k
        """
        # Remover espacios y convertir a mayúsculas
        rut = rut.strip().upper()
        
        # Remover puntos y guiones
        rut = rut.replace(".", "").replace("-", "")
        
        return rut
    
    @staticmethod
    def validate_format(rut):
        """Valida que el formato del RUT sea correcto"""
        # Patrón: 7-8 dígitos seguidos de un dígito o K
        pattern = r'^[0-9]{7,8}[0-9K]$'
        return bool(re.match(pattern, rut))
    
    @staticmethod
    def calculate_dv(rut_numbers):
        """Calcula el dígito verificador de un RUT"""
        # Algoritmo módulo 11
        suma = 0
        multiplo = 2
        
        # Recorrer el RUT de derecha a izquierda
        for i in range(len(rut_numbers) - 1, -1, -1):
            suma += int(rut_numbers[i]) * multiplo
            multiplo += 1
            if multiplo > 7:
                multiplo = 2
        
        # Calcular dígito verificador
        resultado = 11 - (suma % 11)
        
        if resultado == 11:
            return '0'
        elif resultado == 10:
            return 'K'
        else:
            return str(resultado)
    
    @classmethod
    def validate(cls, rut):
        """
        Valida completamente un RUT chileno
        Retorna tupla (es_valido, mensaje)
        """
        # Limpiar RUT
        clean = cls.clean_rut(rut)
        
        # Validar formato
        if not cls.validate_format(clean):
            return False, "Formato de RUT inválido"
        
        # Separar números y dígito verificador
        rut_numbers = clean[:-1]
        provided_dv = clean[-1]
        
        # Validar longitud mínima
        if len(rut_numbers) < 7:
            return False, "RUT muy corto"
        
        # Validar que no sea un RUT conocido como inválido
        invalid_ruts = ['11111111', '22222222', '33333333', '44444444', 
                       '55555555', '66666666', '77777777', '88888888', '99999999']
        if rut_numbers in invalid_ruts:
            return False, "RUT inválido (secuencia repetida)"
        
        # Calcular dígito verificador
        calculated_dv = cls.calculate_dv(rut_numbers)
        
        # Comparar con el proporcionado
        if calculated_dv == provided_dv:
            return True, "RUT válido"
        else:
            return False, f"Dígito verificador incorrecto (debería ser {calculated_dv})"
    
    @classmethod
    def format_rut(cls, rut):
        """Formatea un RUT con puntos y guión"""
        clean = cls.clean_rut(rut)
        if not cls.validate_format(clean):
            return None
        
        rut_numbers = clean[:-1]
        dv = clean[-1]
        
        # Formatear con puntos
        formatted = ""
        for i, digit in enumerate(reversed(rut_numbers)):
            if i > 0 and i % 3 == 0:
                formatted = "." + formatted
            formatted = digit + formatted
        
        return f"{formatted}-{dv}"


def main():
    """Función principal para uso desde línea de comandos"""
    if len(sys.argv) != 2:
        print("Uso: python validate_rut.py <RUT>")
        print("Ejemplo: python validate_rut.py 12345678-5")
        sys.exit(1)
    
    rut = sys.argv[1]
    validator = RutValidator()
    
    # Validar
    is_valid, message = validator.validate(rut)
    
    # Mostrar resultado
    if is_valid:
        formatted = validator.format_rut(rut)
        print(f"✓ {message}")
        print(f"RUT formateado: {formatted}")
        sys.exit(0)
    else:
        print(f"✗ {message}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Ejemplos de uso:
# python validate_rut.py 12345678-5
# python validate_rut.py 12.345.678-5
# python validate_rut.py 123456785
# python validate_rut.py 11222333-k
