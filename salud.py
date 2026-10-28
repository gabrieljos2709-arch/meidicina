"""SistemaRural-PE: prototipo académico alineado con el diagrama UML.

Incluye pacientes, usuarios, profesionales, citas Factory, atenciones, recetas,
medicamentos, detalles de receta, reportes, repositorios y configuración Singleton.

Ejecución:
    python sistema_rural_pe.py

Todas las personas y datos de la demostración son ficticios. Los datos viven en
memoria y desaparecen al cerrar el programa; no usar para atención clínica real.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from datetime import date, datetime, timedelta
from enum import Enum
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Generic, Iterable, List, Mapping, Optional, Sequence, Tuple, TypeVar
import csv
import json
import unittest
import os


# ================================================================
# 1. CONFIGURACIÓN (Singleton)
# ================================================================

class ConfiguracionSistema:
    """Una única instancia de configuración para el proceso de la aplicación."""

    _instancia: Optional["ConfiguracionSistema"] = None
    _lock = Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> "ConfiguracionSistema":
        with cls._lock:
            if cls._instancia is None:
                cls._instancia = super().__new__(cls)
        return cls._instancia

    def __init__(
        self,
        base_datos: str = "memoria",
        version: str = "1.0.0",
        entorno: str = "desarrollo",
    ) -> None:
        # El constructor puede llamarse varias veces, pero la configuración se
        # inicializa únicamente en la primera construcción de la instancia.
        if getattr(self, "_inicializado", False):
            return
        self._base_datos = self._texto_obligatorio(base_datos, "base de datos")
        self._version = self._texto_obligatorio(version, "versión")
        self._entorno = self._texto_obligatorio(entorno, "entorno")
        self._inicializado = True

    @staticmethod
    def _texto_obligatorio(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} no puede estar vacío.")
        return valor.strip()

    @classmethod
    def obtener_instancia(cls) -> "ConfiguracionSistema":
        return cls()

    @property
    def base_datos(self) -> str:
        return self._base_datos

    @property
    def version(self) -> str:
        return self._version

    @property
    def entorno(self) -> str:
        return self._entorno

    def obtener_base_datos(self) -> str:
        return self._base_datos

    def establecer_base_datos(self, valor: str) -> None:
        self._base_datos = self._texto_obligatorio(valor, "base de datos")

    def establecer_entorno(self, valor: str) -> None:
        self._entorno = self._texto_obligatorio(valor, "entorno")


# ================================================================
# 2. USUARIO Y SEGURIDAD BÁSICA DE CREDENCIALES
# ================================================================

class Usuario:
    """Cuenta del personal que utiliza el sistema; no equivale a un paciente."""

    ITERACIONES_HASH = 180_000

    def __init__(self, id_usuario: str, nombre: str, correo: str,
                 contrasena: str, rol: str) -> None:
        self._id_usuario = self._requerido(id_usuario, "ID de usuario").upper()
        self._nombre = self._requerido(nombre, "nombre")
        self._correo = self._requerido(correo, "correo electrónico").lower()
        if "@" not in self._correo or "." not in self._correo.split("@")[-1]:
            raise ValueError("El correo electrónico no tiene un formato válido.")
        self._rol = self._requerido(rol, "rol").lower()
        self._salt = os.urandom(16)
        self._hash_contrasena = self._crear_hash(self._validar_contrasena(contrasena))
        self._sesion_activa = False

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El {campo} es obligatorio.")
        return valor.strip()

    @staticmethod
    def _validar_contrasena(contrasena: str) -> str:
        if not isinstance(contrasena, str) or len(contrasena) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres.")
        return contrasena

    def _crear_hash(self, contrasena: str) -> bytes:
        return pbkdf2_hmac("sha256", contrasena.encode("utf-8"), self._salt,
                           self.ITERACIONES_HASH)

    @property
    def id_usuario(self) -> str:
        return self._id_usuario

    @property
    def nombre(self) -> str:
        return self._nombre

    @property
    def correo(self) -> str:
        return self._correo

    @property
    def rol(self) -> str:
        return self._rol

    @property
    def sesion_activa(self) -> bool:
        return self._sesion_activa

    def autenticar(self, contrasena: str) -> bool:
        """Autentica comparando hashes; nunca guarda la contraseña en texto plano."""
        if not isinstance(contrasena, str):
            return False
        hash_prueba = self._crear_hash(contrasena)
        correcto = compare_digest(hash_prueba, self._hash_contrasena)
        if correcto:
            self._sesion_activa = True
        return correcto

    def cambiar_contrasena(self, actual: str, nueva: str) -> None:
        if not self.autenticar(actual):
            raise PermissionError("La contraseña actual es incorrecta.")
        nueva = self._validar_contrasena(nueva)
        self._salt = os.urandom(16)
        self._hash_contrasena = self._crear_hash(nueva)
        self._sesion_activa = True

    def cerrar_sesion(self) -> None:
        self._sesion_activa = False

    def __repr__(self) -> str:
        return f"Usuario(id_usuario={self._id_usuario!r}, rol={self._rol!r})"


# ================================================================
# 3. PACIENTES
# ================================================================

class Paciente:
    """Entidad de paciente; los datos de identificación no se imprimen en repr."""

    CAMPOS_ACTUALIZABLES = {"nombres", "apellidos", "sexo", "telefono", "direccion"}

    def __init__(self, id_paciente: str, dni: str, nombres: str, apellidos: str,
                 fecha_nacimiento: date, sexo: str, telefono: str = "",
                 direccion: str = "") -> None:
        self._id_paciente = self._requerido(id_paciente, "ID de paciente").upper()
        self._dni = self._requerido(dni, "DNI")
        if not self._dni.isdigit() or len(self._dni) != 8:
            raise ValueError("El DNI debe contener exactamente 8 dígitos.")
        self._nombres = self._requerido(nombres, "nombres")
        self._apellidos = self._requerido(apellidos, "apellidos")
        if not isinstance(fecha_nacimiento, date) or isinstance(fecha_nacimiento, datetime):
            raise ValueError("La fecha de nacimiento debe ser de tipo date.")
        if fecha_nacimiento > date.today():
            raise ValueError("La fecha de nacimiento no puede estar en el futuro.")
        self._fecha_nacimiento = fecha_nacimiento
        self._sexo = self._requerido(sexo, "sexo")
        self._telefono = telefono.strip() if isinstance(telefono, str) else ""
        self._direccion = direccion.strip() if isinstance(direccion, str) else ""
        self._registrado = False
        self._historial: List[Atencion] = []

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_paciente(self) -> str:
        return self._id_paciente

    @property
    def dni(self) -> str:
        return self._dni

    @property
    def nombres(self) -> str:
        return self._nombres

    @property
    def apellidos(self) -> str:
        return self._apellidos

    @property
    def fecha_nacimiento(self) -> date:
        return self._fecha_nacimiento

    @property
    def sexo(self) -> str:
        return self._sexo

    @property
    def telefono(self) -> str:
        return self._telefono

    @property
    def direccion(self) -> str:
        return self._direccion

    @property
    def registrado(self) -> bool:
        return self._registrado

    def registrar(self) -> None:
        self._registrado = True

    def actualizar_datos(self, **datos: str) -> None:
        desconocidos = set(datos) - self.CAMPOS_ACTUALIZABLES
        if desconocidos:
            raise ValueError(f"Campos no actualizables: {', '.join(sorted(desconocidos))}.")
        for campo, valor in datos.items():
            if not isinstance(valor, str) or not valor.strip():
                raise ValueError(f"El campo {campo} no puede estar vacío.")
        for campo, valor in datos.items():
            setattr(self, f"_{campo}", valor.strip())

    def obtener_historial(self) -> Tuple["Atencion", ...]:
        return tuple(self._historial)

    def _agregar_atencion(self, atencion: "Atencion") -> None:
        if atencion.cita.paciente.id_paciente != self._id_paciente:
            raise ValueError("La atención no pertenece a este paciente.")
        if all(a.id_atencion != atencion.id_atencion for a in self._historial):
            self._historial.append(atencion)

    def __repr__(self) -> str:
        return f"Paciente(id_paciente={self._id_paciente!r})"


# ================================================================
# 4. PROFESIONALES, MÉDICOS Y ENFERMERAS
# ================================================================

class ProfesionalSalud(ABC):
    def __init__(self, id_profesional: str, nombre: str, apellido: str,
                 especialidad: str, colegiatura: str) -> None:
        self._id_profesional = self._requerido(id_profesional, "ID profesional").upper()
        self._nombre = self._requerido(nombre, "nombre")
        self._apellido = self._requerido(apellido, "apellido")
        self._especialidad = self._requerido(especialidad, "especialidad")
        self._colegiatura = self._requerido(colegiatura, "colegiatura")
        self._disponibilidades: List[Tuple[datetime, datetime]] = []

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_profesional(self) -> str:
        return self._id_profesional

    @property
    def nombre_completo(self) -> str:
        return f"{self._nombre} {self._apellido}"

    @property
    def especialidad(self) -> str:
        return self._especialidad

    @property
    def colegiatura(self) -> str:
        return self._colegiatura

    @property
    @abstractmethod
    def tipo_profesional(self) -> str:
        raise NotImplementedError

    def actualizar_disponibilidad(self, inicio: datetime, fin: datetime) -> None:
        if not isinstance(inicio, datetime) or not isinstance(fin, datetime) or fin <= inicio:
            raise ValueError("El intervalo de disponibilidad debe tener fechas válidas.")
        if any(inicio < fin_existente and inicio_existente < fin
               for inicio_existente, fin_existente in self._disponibilidades):
            raise ValueError("El intervalo se superpone con otra disponibilidad registrada.")
        self._disponibilidades.append((inicio, fin))
        self._disponibilidades.sort(key=lambda intervalo: intervalo[0])

    def esta_disponible(self, inicio: datetime, fin: datetime) -> bool:
        # Sin intervalos explícitos se permite programar; la agenda sigue
        # controlando cruces de citas. Al registrar intervalos, se aplican.
        if not self._disponibilidades:
            return True
        return any(inicio >= desde and fin <= hasta for desde, hasta in self._disponibilidades)

    def ver_agenda(self, citas: Iterable["Cita"]) -> List["Cita"]:
        agenda = [c for c in citas if c.profesional.id_profesional == self._id_profesional
                  and c.estado != EstadoCita.CANCELADA]
        return sorted(agenda, key=lambda c: c.fecha)

    def registrar_atencion(self, cita: "Cita", id_atencion: str,
                           diagnostico: str, observaciones: str = "",
                           fecha_atencion: Optional[datetime] = None) -> "Atencion":
        if cita.profesional.id_profesional != self._id_profesional:
            raise ValueError("El profesional no está asignado a esta cita.")
        if cita.estado != EstadoCita.PROGRAMADA:
            raise ValueError("Solo se puede registrar una atención para una cita programada.")
        return Atencion(id_atencion, cita, fecha_atencion or datetime.now(),
                        diagnostico, observaciones)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id_profesional={self._id_profesional!r})"


class Medico(ProfesionalSalud):
    def __init__(self, id_profesional: str, nombre: str, apellido: str,
                 especialidad: str, colegiatura: str, numero_cmp: str) -> None:
        super().__init__(id_profesional, nombre, apellido, especialidad, colegiatura)
        self._numero_cmp = self._requerido(numero_cmp, "número CMP")

    @property
    def numero_cmp(self) -> str:
        return self._numero_cmp

    @property
    def tipo_profesional(self) -> str:
        return "médico"

    def atender_paciente(self, paciente: Paciente, cita: "Cita", id_atencion: str,
                         diagnostico: str, observaciones: str = "",
                         fecha_atencion: Optional[datetime] = None) -> "Atencion":
        if cita.paciente.id_paciente != paciente.id_paciente:
            raise ValueError("El paciente no corresponde a la cita seleccionada.")
        return self.registrar_atencion(cita, id_atencion, diagnostico,
                                       observaciones, fecha_atencion)


class Enfermera(ProfesionalSalud):
    def __init__(self, id_profesional: str, nombre: str, apellido: str,
                 especialidad: str, colegiatura: str, codigo_enfermera: str) -> None:
        super().__init__(id_profesional, nombre, apellido, especialidad, colegiatura)
        self._codigo_enfermera = self._requerido(codigo_enfermera, "código de enfermería")

    @property
    def codigo_enfermera(self) -> str:
        return self._codigo_enfermera

    @property
    def tipo_profesional(self) -> str:
        return "enfermera"

    def registrar_signos_vitales(self, atencion: "Atencion", *,
                                 temperatura_c: float,
                                 frecuencia_cardiaca: int,
                                 presion_arterial: str,
                                 frecuencia_respiratoria: int,
                                 saturacion_oxigeno: int) -> Dict[str, Any]:
        if not isinstance(atencion, Atencion):
            raise TypeError("Se requiere una instancia de Atencion.")
        if not 30 <= float(temperatura_c) <= 45:
            raise ValueError("La temperatura debe estar entre 30 y 45 °C.")
        if not 20 <= frecuencia_cardiaca <= 250:
            raise ValueError("La frecuencia cardíaca debe estar entre 20 y 250 lpm.")
        if not 5 <= frecuencia_respiratoria <= 80:
            raise ValueError("La frecuencia respiratoria debe estar entre 5 y 80 rpm.")
        if not 50 <= saturacion_oxigeno <= 100:
            raise ValueError("La saturación debe estar entre 50 y 100 %.")
        if not isinstance(presion_arterial, str) or "/" not in presion_arterial:
            raise ValueError("La presión arterial debe expresarse como 'sistólica/diastólica'.")
        signos = {
            "temperatura_c": float(temperatura_c),
            "frecuencia_cardiaca_lpm": frecuencia_cardiaca,
            "presion_arterial": presion_arterial.strip(),
            "frecuencia_respiratoria_rpm": frecuencia_respiratoria,
            "saturacion_oxigeno_pct": saturacion_oxigeno,
            "registrado_por": self._id_profesional,
        }
        atencion.registrar_signos_vitales(signos)
        return signos.copy()


# ================================================================
# 5. CITAS: ABSTRACCIÓN, HERENCIA Y POLIMORFISMO
# ================================================================

class EstadoCita(str, Enum):
    PENDIENTE = "pendiente"
    PROGRAMADA = "programada"
    COMPLETADA = "completada"
    CANCELADA = "cancelada"


class Cita(ABC):
    def __init__(self, id_cita: str, paciente: Paciente,
                 profesional: ProfesionalSalud, fecha: datetime,
                 motivo: str) -> None:
        self._id_cita = self._requerido(id_cita, "ID de cita").upper()
        if not isinstance(paciente, Paciente):
            raise TypeError("La cita debe estar asociada a un Paciente.")
        if not isinstance(profesional, ProfesionalSalud):
            raise TypeError("La cita debe estar asociada a un ProfesionalSalud.")
        if not isinstance(fecha, datetime):
            raise ValueError("La fecha de la cita debe ser un datetime.")
        self._paciente = paciente
        self._profesional = profesional
        self._fecha = fecha
        self._motivo = self._requerido(motivo, "motivo")
        self._estado = EstadoCita.PENDIENTE

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_cita(self) -> str:
        return self._id_cita

    @property
    def paciente(self) -> Paciente:
        return self._paciente

    @property
    def profesional(self) -> ProfesionalSalud:
        return self._profesional

    @property
    def fecha(self) -> datetime:
        return self._fecha

    @property
    def motivo(self) -> str:
        return self._motivo

    @property
    def estado(self) -> EstadoCita:
        return self._estado

    @property
    @abstractmethod
    def tipo(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def duracion_minutos(self) -> int:
        raise NotImplementedError

    @property
    def fecha_fin(self) -> datetime:
        return self._fecha + timedelta(minutes=self.duracion_minutos)

    def programar(self) -> None:
        if self._estado != EstadoCita.PENDIENTE:
            raise ValueError("Solo una cita pendiente puede programarse.")
        self._estado = EstadoCita.PROGRAMADA

    def cancelar(self) -> None:
        if self._estado != EstadoCita.PROGRAMADA:
            raise ValueError("Solo se puede cancelar una cita programada.")
        self._estado = EstadoCita.CANCELADA

    def reprogramar(self, nueva_fecha: datetime) -> None:
        if self._estado != EstadoCita.PROGRAMADA:
            raise ValueError("Solo se puede reprogramar una cita programada.")
        if not isinstance(nueva_fecha, datetime):
            raise ValueError("La nueva fecha debe ser datetime.")
        self._fecha = nueva_fecha

    def completar(self) -> None:
        if self._estado != EstadoCita.PROGRAMADA:
            raise ValueError("Solo se puede completar una cita programada.")
        self._estado = EstadoCita.COMPLETADA

    def cambiar_estado(self, nuevo_estado: EstadoCita) -> None:
        """Permite cambios válidos sin permitir resucitar citas canceladas."""
        if not isinstance(nuevo_estado, EstadoCita):
            raise ValueError("El estado debe pertenecer a EstadoCita.")
        transiciones = {
            EstadoCita.PENDIENTE: {EstadoCita.PROGRAMADA, EstadoCita.CANCELADA},
            EstadoCita.PROGRAMADA: {EstadoCita.COMPLETADA, EstadoCita.CANCELADA},
            EstadoCita.COMPLETADA: set(),
            EstadoCita.CANCELADA: set(),
        }
        if nuevo_estado not in transiciones[self._estado]:
            raise ValueError(f"Transición inválida: {self._estado.value} -> {nuevo_estado.value}.")
        self._estado = nuevo_estado

    def __repr__(self) -> str:
        return (f"Cita(id_cita={self._id_cita!r}, tipo={self.tipo!r}, "
                f"fecha={self._fecha.isoformat()!r}, estado={self._estado.value!r})")


class CitaGeneral(Cita):
    def __init__(self, *args: Any, tipo_consulta: str = "consulta general", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._tipo_consulta = self._requerido(tipo_consulta, "tipo de consulta")

    @property
    def tipo(self) -> str:
        return "general"

    @property
    def duracion_minutos(self) -> int:
        return 30

    @property
    def tipo_consulta(self) -> str:
        return self._tipo_consulta

    def registrar_atencion(self) -> str:
        return f"Atención general preparada para la cita {self.id_cita}."


class CitaControl(Cita):
    def __init__(self, *args: Any, diagnostico_previo: str,
                 proximo_control: Optional[date] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._diagnostico_previo = self._requerido(diagnostico_previo, "diagnóstico previo")
        if proximo_control is not None and not isinstance(proximo_control, date):
            raise ValueError("El próximo control debe ser de tipo date.")
        self._proximo_control = proximo_control

    @property
    def tipo(self) -> str:
        return "control"

    @property
    def duracion_minutos(self) -> int:
        return 20

    @property
    def diagnostico_previo(self) -> str:
        return self._diagnostico_previo

    @property
    def proximo_control(self) -> Optional[date]:
        return self._proximo_control

    def registrar_control(self) -> str:
        return f"Control de seguimiento preparado para la cita {self.id_cita}."


class FabricaCitas:
    """Factory: decide qué clase de cita concreta construir."""

    TIPOS_DISPONIBLES = ("general", "control")

    @staticmethod
    def obtener_tipos_disponibles() -> Tuple[str, ...]:
        return FabricaCitas.TIPOS_DISPONIBLES

    @staticmethod
    def crear_cita(tipo: str, **datos: Any) -> Cita:
        if not isinstance(tipo, str):
            raise ValueError("El tipo de cita debe ser texto.")
        tipo = tipo.strip().lower()
        if tipo == "general":
            return CitaGeneral(**datos)
        if tipo == "control":
            if not datos.get("diagnostico_previo"):
                raise ValueError("Una cita de control requiere diagnóstico previo.")
            return CitaControl(**datos)
        raise ValueError("Tipo desconocido. Use 'general' o 'control'.")


# ================================================================
# 6. ATENCIÓN Y RECETA
# ================================================================

class Atencion:
    def __init__(self, id_atencion: str, cita: Cita, fecha_atencion: datetime,
                 diagnostico: str, observaciones: str = "") -> None:
        if not isinstance(cita, Cita):
            raise TypeError("La atención debe corresponder a una cita.")
        self._id_atencion = self._requerido(id_atencion, "ID de atención").upper()
        if not isinstance(fecha_atencion, datetime):
            raise ValueError("La fecha de atención debe ser datetime.")
        self._cita = cita
        self._fecha_atencion = fecha_atencion
        self._diagnostico = self._requerido(diagnostico, "diagnóstico")
        self._observaciones = observaciones.strip() if isinstance(observaciones, str) else ""
        self._signos_vitales: Dict[str, Any] = {}
        self._receta: Optional[Receta] = None
        self._registrada = False

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_atencion(self) -> str:
        return self._id_atencion

    @property
    def cita(self) -> Cita:
        return self._cita

    @property
    def fecha_atencion(self) -> datetime:
        return self._fecha_atencion

    @property
    def diagnostico(self) -> str:
        return self._diagnostico

    @property
    def observaciones(self) -> str:
        return self._observaciones

    @property
    def signos_vitales(self) -> Mapping[str, Any]:
        return dict(self._signos_vitales)

    @property
    def receta(self) -> Optional["Receta"]:
        return self._receta

    @property
    def registrada(self) -> bool:
        return self._registrada

    def registrar_signos_vitales(self, signos: Mapping[str, Any]) -> None:
        if self._registrada and self._signos_vitales:
            raise ValueError("Los signos vitales de esta atención ya fueron registrados.")
        if not signos:
            raise ValueError("Debe proporcionarse al menos un signo vital.")
        self._signos_vitales = dict(signos)

    def registrar(self) -> None:
        if self._registrada:
            raise ValueError("La atención ya fue registrada.")
        self._registrada = True

    def generar_receta(self, id_receta: str, indicaciones: str) -> "Receta":
        if not self._registrada:
            raise ValueError("Registre la atención antes de generar una receta.")
        if self._receta is not None:
            raise ValueError("Esta atención ya tiene una receta asociada.")
        self._receta = Receta(id_receta, datetime.now(), indicaciones, self)
        return self._receta

    def __repr__(self) -> str:
        return f"Atencion(id_atencion={self._id_atencion!r}, cita={self._cita.id_cita!r})"


class EstadoReceta(str, Enum):
    BORRADOR = "borrador"
    VALIDADA = "validada"
    EMITIDA = "emitida"
    CANCELADA = "cancelada"


class Receta:
    def __init__(self, id_receta: str, fecha_emision: datetime,
                 indicaciones: str, atencion: Atencion) -> None:
        self._id_receta = self._requerido(id_receta, "ID de receta").upper()
        if not isinstance(fecha_emision, datetime):
            raise ValueError("La fecha de emisión debe ser datetime.")
        if not isinstance(atencion, Atencion):
            raise TypeError("La receta debe pertenecer a una atención.")
        self._fecha_emision = fecha_emision
        self._indicaciones = self._requerido(indicaciones, "indicaciones")
        self._atencion = atencion
        self._detalles: List[DetalleReceta] = []
        self._estado = EstadoReceta.BORRADOR

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_receta(self) -> str:
        return self._id_receta

    @property
    def fecha_emision(self) -> datetime:
        return self._fecha_emision

    @property
    def indicaciones(self) -> str:
        return self._indicaciones

    @property
    def atencion(self) -> Atencion:
        return self._atencion

    @property
    def detalles(self) -> Tuple["DetalleReceta", ...]:
        return tuple(self._detalles)

    @property
    def estado(self) -> EstadoReceta:
        return self._estado

    def agregar_detalle(self, detalle: "DetalleReceta") -> None:
        if self._estado != EstadoReceta.BORRADOR:
            raise ValueError("Solo se agregan detalles a una receta en borrador.")
        if not isinstance(detalle, DetalleReceta):
            raise TypeError("El detalle debe ser una instancia de DetalleReceta.")
        if any(d.id_detalle == detalle.id_detalle for d in self._detalles):
            raise ValueError("Ya existe un detalle con ese ID en esta receta.")
        detalle.validar_dosis()
        self._detalles.append(detalle)

    def validar(self) -> bool:
        if self._estado != EstadoReceta.BORRADOR:
            raise ValueError("Solo una receta en borrador puede validarse.")
        if not self._detalles:
            raise ValueError("La receta debe contener al menos un medicamento.")
        for detalle in self._detalles:
            detalle.validar_dosis()
        consumo = Counter()
        medicamentos: Dict[str, Medicamento] = {}
        for detalle in self._detalles:
            consumo[detalle.medicamento.id_medicamento] += detalle.cantidad
            medicamentos[detalle.medicamento.id_medicamento] = detalle.medicamento
        for id_medicamento, cantidad in consumo.items():
            if not medicamentos[id_medicamento].verificar_stock(cantidad):
                raise ValueError(f"Stock insuficiente para el medicamento {id_medicamento}.")
        self._estado = EstadoReceta.VALIDADA
        return True

    def emitir(self) -> None:
        if self._estado != EstadoReceta.VALIDADA:
            raise ValueError("La receta debe validarse antes de emitirse.")
        # Se valida primero todo el stock; luego se descuenta para evitar una
        # emisión parcialmente aplicada si falta algún medicamento.
        consumo = Counter()
        medicamentos: Dict[str, Medicamento] = {}
        for detalle in self._detalles:
            consumo[detalle.medicamento.id_medicamento] += detalle.cantidad
            medicamentos[detalle.medicamento.id_medicamento] = detalle.medicamento
        for id_medicamento, cantidad in consumo.items():
            if not medicamentos[id_medicamento].verificar_stock(cantidad):
                raise ValueError(f"Stock insuficiente para el medicamento {id_medicamento}.")
        for id_medicamento, cantidad in consumo.items():
            medicamentos[id_medicamento].actualizar_stock(-cantidad)
        self._estado = EstadoReceta.EMITIDA

    def cancelar(self) -> None:
        if self._estado == EstadoReceta.EMITIDA:
            raise ValueError("Una receta emitida no puede cancelarse en este prototipo.")
        if self._estado == EstadoReceta.CANCELADA:
            raise ValueError("La receta ya está cancelada.")
        self._estado = EstadoReceta.CANCELADA

    def imprimir(self) -> str:
        if self._estado != EstadoReceta.EMITIDA:
            raise ValueError("Solo se puede imprimir una receta emitida.")
        lineas = [
            f"RECETA {self._id_receta}",
            f"Fecha: {self._fecha_emision:%Y-%m-%d %H:%M}",
            f"Atención: {self._atencion.id_atencion}",
            f"Indicaciones: {self._indicaciones}",
            "Medicamentos:",
        ]
        for detalle in self._detalles:
            lineas.append(
                f"- {detalle.medicamento.nombre}: {detalle.dosis}; "
                f"{detalle.frecuencia}; {detalle.duracion}; "
                f"unidades: {detalle.cantidad}"
            )
        return "\n".join(lineas)


# ================================================================
# 7. INVENTARIO Y DETALLES DE RECETA
# ================================================================

class Medicamento:
    def __init__(self, id_medicamento: str, nombre: str, descripcion: str,
                 stock: int, precio: float, laboratorio: str) -> None:
        self._id_medicamento = self._requerido(id_medicamento, "ID de medicamento").upper()
        self._nombre = self._requerido(nombre, "nombre del medicamento")
        self._descripcion = self._requerido(descripcion, "descripción")
        if not isinstance(stock, int) or isinstance(stock, bool) or stock < 0:
            raise ValueError("El stock inicial debe ser un entero no negativo.")
        if not isinstance(precio, (int, float)) or isinstance(precio, bool) or precio < 0:
            raise ValueError("El precio debe ser un número no negativo.")
        self._stock = stock
        self._precio = float(precio)
        self._laboratorio = self._requerido(laboratorio, "laboratorio")

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_medicamento(self) -> str:
        return self._id_medicamento

    @property
    def nombre(self) -> str:
        return self._nombre

    @property
    def descripcion(self) -> str:
        return self._descripcion

    @property
    def stock(self) -> int:
        return self._stock

    @property
    def precio(self) -> float:
        return self._precio

    @property
    def laboratorio(self) -> str:
        return self._laboratorio

    def actualizar_stock(self, cantidad: int) -> None:
        """Aplica un ajuste con signo: positivo ingresa stock, negativo dispensa."""
        if not isinstance(cantidad, int) or isinstance(cantidad, bool):
            raise ValueError("El ajuste de stock debe ser un entero.")
        nuevo_stock = self._stock + cantidad
        if nuevo_stock < 0:
            raise ValueError("No se puede dejar el stock por debajo de cero.")
        self._stock = nuevo_stock

    def verificar_stock(self, cantidad: int = 1) -> bool:
        if not isinstance(cantidad, int) or isinstance(cantidad, bool) or cantidad < 0:
            raise ValueError("La cantidad a verificar debe ser un entero no negativo.")
        return self._stock >= cantidad

    def __repr__(self) -> str:
        return f"Medicamento(id_medicamento={self._id_medicamento!r}, stock={self._stock})"


class DetalleReceta:
    def __init__(self, id_detalle: str, medicamento: Medicamento, dosis: str,
                 frecuencia: str, duracion: str, cantidad: int = 1) -> None:
        self._id_detalle = self._requerido(id_detalle, "ID de detalle").upper()
        if not isinstance(medicamento, Medicamento):
            raise TypeError("El detalle debe hacer referencia a un Medicamento.")
        self._medicamento = medicamento
        self._dosis = self._requerido(dosis, "dosis")
        self._frecuencia = self._requerido(frecuencia, "frecuencia")
        self._duracion = self._requerido(duracion, "duración")
        if not isinstance(cantidad, int) or isinstance(cantidad, bool) or cantidad <= 0:
            raise ValueError("La cantidad debe ser un entero positivo.")
        self._cantidad = cantidad

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_detalle(self) -> str:
        return self._id_detalle

    @property
    def medicamento(self) -> Medicamento:
        return self._medicamento

    @property
    def dosis(self) -> str:
        return self._dosis

    @property
    def frecuencia(self) -> str:
        return self._frecuencia

    @property
    def duracion(self) -> str:
        return self._duracion

    @property
    def cantidad(self) -> int:
        return self._cantidad

    def validar_dosis(self) -> bool:
        if not self._dosis or not self._frecuencia or not self._duracion:
            raise ValueError("Dosis, frecuencia y duración son obligatorias.")
        if self._cantidad <= 0:
            raise ValueError("La cantidad debe ser mayor que cero.")
        return True


# ================================================================
# 8. REPOSITORIOS (Repository)
# ================================================================

T = TypeVar("T")


class IRepositorio(ABC, Generic[T]):
    """Contrato de persistencia independiente del almacenamiento concreto."""

    @abstractmethod
    def guardar(self, objeto: T) -> None:
        raise NotImplementedError

    @abstractmethod
    def obtener(self, identificador: str) -> Optional[T]:
        raise NotImplementedError

    @abstractmethod
    def listar(self) -> Tuple[T, ...]:
        raise NotImplementedError

    @abstractmethod
    def eliminar(self, identificador: str) -> bool:
        raise NotImplementedError


class RepositorioEnMemoria(IRepositorio[T], Generic[T]):
    """Implementación genérica de repositorio usando un diccionario."""

    def __init__(self, atributo_id: str) -> None:
        self._atributo_id = atributo_id
        self._datos: Dict[str, T] = {}

    def _clave(self, objeto: T) -> str:
        try:
            clave = getattr(objeto, self._atributo_id)
        except AttributeError as exc:
            raise TypeError(f"El objeto no contiene el identificador {self._atributo_id}.") from exc
        if not isinstance(clave, str) or not clave.strip():
            raise ValueError("El identificador del objeto debe ser un texto no vacío.")
        return clave.strip().upper()

    def guardar(self, objeto: T) -> None:
        clave = self._clave(objeto)
        if clave in self._datos:
            raise ValueError(f"Ya existe un registro con el identificador {clave}.")
        self._datos[clave] = objeto

    def obtener(self, identificador: str) -> Optional[T]:
        if not isinstance(identificador, str) or not identificador.strip():
            return None
        return self._datos.get(identificador.strip().upper())

    def listar(self) -> Tuple[T, ...]:
        return tuple(self._datos.values())

    def eliminar(self, identificador: str) -> bool:
        return self._datos.pop(identificador.strip().upper(), None) is not None


class RepositorioPacientes(RepositorioEnMemoria[Paciente]):
    def __init__(self) -> None:
        super().__init__("id_paciente")

    def buscar_por_dni(self, dni: str) -> Optional[Paciente]:
        return next((p for p in self.listar() if p.dni == dni), None)


class RepositorioCitas(RepositorioEnMemoria[Cita]):
    def __init__(self) -> None:
        super().__init__("id_cita")

    def buscar_por_fecha(self, fecha: date) -> Tuple[Cita, ...]:
        return tuple(c for c in self.listar() if c.fecha.date() == fecha)


class RepositorioProfesionales(RepositorioEnMemoria[ProfesionalSalud]):
    def __init__(self) -> None:
        super().__init__("id_profesional")


class RepositorioAtenciones(RepositorioEnMemoria[Atencion]):
    def __init__(self) -> None:
        super().__init__("id_atencion")


class RepositorioMedicamentos(RepositorioEnMemoria[Medicamento]):
    def __init__(self) -> None:
        super().__init__("id_medicamento")


class RepositorioRecetas(RepositorioEnMemoria[Receta]):
    def __init__(self) -> None:
        super().__init__("id_receta")


class RepositorioUsuarios(RepositorioEnMemoria[Usuario]):
    def __init__(self) -> None:
        super().__init__("id_usuario")


# ================================================================
# 9. REPORTES Y EXPORTACIÓN
# ================================================================

class Reporte:
    def __init__(self, id_reporte: str, tipo: str,
                 fecha_generacion: Optional[datetime] = None) -> None:
        self._id_reporte = self._requerido(id_reporte, "ID de reporte").upper()
        self._tipo = self._requerido(tipo, "tipo de reporte")
        self._fecha_generacion = fecha_generacion or datetime.now()
        self._datos: Dict[str, Any] = {}

    @staticmethod
    def _requerido(valor: str, campo: str) -> str:
        if not isinstance(valor, str) or not valor.strip():
            raise ValueError(f"El campo {campo} es obligatorio.")
        return valor.strip()

    @property
    def id_reporte(self) -> str:
        return self._id_reporte

    @property
    def fecha_generacion(self) -> datetime:
        return self._fecha_generacion

    @property
    def tipo(self) -> str:
        return self._tipo

    @property
    def datos(self) -> Mapping[str, Any]:
        return dict(self._datos)

    def generar(self, datos: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(datos, Mapping):
            raise TypeError("Los datos del reporte deben ser un diccionario o Mapping.")
        self._datos = dict(datos)
        self._fecha_generacion = datetime.now()
        return self.datos.copy()

    def exportar_csv(self, ruta: str | Path) -> Path:
        """Exporta pares clave/valor en CSV, usando solo la biblioteca estándar."""
        destino = Path(ruta)
        destino.parent.mkdir(parents=True, exist_ok=True)
        with destino.open("w", newline="", encoding="utf-8-sig") as archivo:
            escritor = csv.writer(archivo)
            escritor.writerow(["indicador", "valor"])
            for clave, valor in self._datos.items():
                escritor.writerow([clave, json.dumps(valor, ensure_ascii=False, default=str)])
        return destino

    def exportar_excel(self, ruta: str | Path) -> Path:
        """Exporta a XLSX. Requiere instalar openpyxl: pip install openpyxl."""
        try:
            from openpyxl import Workbook
        except ImportError as exc:
            raise RuntimeError("Para exportar Excel instala la dependencia: pip install openpyxl") from exc
        destino = Path(ruta)
        destino.parent.mkdir(parents=True, exist_ok=True)
        libro = Workbook()
        hoja = libro.active
        hoja.title = "Reporte"
        hoja.append(["Indicador", "Valor"])
        for clave, valor in self._datos.items():
            hoja.append([clave, json.dumps(valor, ensure_ascii=False, default=str)])
        libro.save(destino)
        return destino

    def exportar_pdf(self, ruta: str | Path) -> Path:
        """Exporta a PDF. Requiere instalar reportlab: pip install reportlab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
        except ImportError as exc:
            raise RuntimeError("Para exportar PDF instala la dependencia: pip install reportlab") from exc
        destino = Path(ruta)
        destino.parent.mkdir(parents=True, exist_ok=True)
        documento = canvas.Canvas(str(destino), pagesize=A4)
        _, alto = A4
        y = alto - 55
        documento.setFont("Helvetica-Bold", 15)
        documento.drawString(45, y, f"SistemaRural-PE | {self._tipo}")
        y -= 24
        documento.setFont("Helvetica", 9)
        documento.drawString(45, y, f"Reporte: {self._id_reporte} | Generado: {self._fecha_generacion:%Y-%m-%d %H:%M}")
        y -= 28
        for clave, valor in self._datos.items():
            linea = f"{clave}: {json.dumps(valor, ensure_ascii=False, default=str)}"
            if y < 50:
                documento.showPage()
                y = alto - 50
                documento.setFont("Helvetica", 9)
            documento.drawString(45, y, linea[:120])
            y -= 16
        documento.save()
        return destino


class GeneradorReportes:
    def __init__(self, repositorio_citas: RepositorioCitas,
                 repositorio_atenciones: RepositorioAtenciones,
                 repositorio_medicamentos: RepositorioMedicamentos) -> None:
        self._citas = repositorio_citas
        self._atenciones = repositorio_atenciones
        self._medicamentos = repositorio_medicamentos
        self._secuencia = 0

    def _nuevo_reporte(self, tipo: str, datos: Mapping[str, Any]) -> Reporte:
        self._secuencia += 1
        reporte = Reporte(f"R-{self._secuencia:04d}", tipo)
        reporte.generar(datos)
        return reporte

    def reporte_citas(self, fecha: Optional[date] = None) -> Reporte:
        citas = list(self._citas.listar())
        if fecha is not None:
            citas = list(filter(lambda c: c.fecha.date() == fecha, citas))
        estados = Counter(c.estado.value for c in citas)
        # map proyecta datos agregados; no usa nombres ni DNI en el reporte.
        tipos = Counter(map(lambda c: c.tipo, citas))
        total = sum(1 for _ in citas)
        datos = {
            "fecha": fecha.isoformat() if fecha else "todas",
            "total_citas": total,
            "pacientes_unicos": len({c.paciente.id_paciente for c in citas}),
            "estados": dict(estados),
            "tipos": dict(tipos),
        }
        return self._nuevo_reporte("citas", datos)

    def reporte_atenciones(self) -> Reporte:
        atenciones = list(self._atenciones.listar())
        por_profesional = Counter(a.cita.profesional.id_profesional for a in atenciones)
        datos = {
            "total_atenciones": len(atenciones),
            "por_profesional": dict(por_profesional),
            "con_signos_vitales": sum(bool(a.signos_vitales) for a in atenciones),
            "con_receta": sum(a.receta is not None for a in atenciones),
        }
        return self._nuevo_reporte("atenciones", datos)

    def reporte_inventario(self) -> Reporte:
        medicamentos = list(self._medicamentos.listar())
        bajo_stock = [m.id_medicamento for m in medicamentos if m.stock < 10]
        valor_inventario = round(sum(m.stock * m.precio for m in medicamentos), 2)
        datos = {
            "medicamentos_registrados": len(medicamentos),
            "unidades_disponibles": sum(m.stock for m in medicamentos),
            "medicamentos_bajo_stock": bajo_stock,
            "valor_inventario_estimado": valor_inventario,
        }
        return self._nuevo_reporte("inventario", datos)


# ================================================================
# 10. SERVICIO DE APLICACIÓN: ORQUESTACIÓN DE CASOS DE USO
# ================================================================

class ServicioSalud:
    """Coordina las operaciones y evita que cada entidad gestione todas las reglas."""

    def __init__(self) -> None:
        self.configuracion = ConfiguracionSistema.obtener_instancia()
        self.pacientes = RepositorioPacientes()
        self.usuarios = RepositorioUsuarios()
        self.profesionales = RepositorioProfesionales()
        self.citas = RepositorioCitas()
        self.atenciones = RepositorioAtenciones()
        self.medicamentos = RepositorioMedicamentos()
        self.recetas = RepositorioRecetas()
        self.reportes = GeneradorReportes(self.citas, self.atenciones, self.medicamentos)

    def registrar_paciente(self, paciente: Paciente) -> Paciente:
        if self.pacientes.buscar_por_dni(paciente.dni):
            raise ValueError("Ya existe un paciente registrado con ese DNI.")
        paciente.registrar()
        self.pacientes.guardar(paciente)
        return paciente

    def registrar_usuario(self, usuario: Usuario) -> Usuario:
        self.usuarios.guardar(usuario)
        return usuario

    def registrar_profesional(self, profesional: ProfesionalSalud) -> ProfesionalSalud:
        self.profesionales.guardar(profesional)
        return profesional

    def registrar_medicamento(self, medicamento: Medicamento) -> Medicamento:
        self.medicamentos.guardar(medicamento)
        return medicamento

    @staticmethod
    def _hay_solapamiento(nueva: Cita, existentes: Iterable[Cita], excluir_id: Optional[str] = None) -> bool:
        for existente in existentes:
            if existente.id_cita == excluir_id or existente.estado in (EstadoCita.CANCELADA, EstadoCita.COMPLETADA):
                continue
            mismo_profesional = existente.profesional.id_profesional == nueva.profesional.id_profesional
            mismo_paciente = existente.paciente.id_paciente == nueva.paciente.id_paciente
            cruza_horario = nueva.fecha < existente.fecha_fin and existente.fecha < nueva.fecha_fin
            if cruza_horario and (mismo_profesional or mismo_paciente):
                return True
        return False

    def programar_cita(self, *, tipo: str, id_cita: str, id_paciente: str,
                       id_profesional: str, fecha: datetime, motivo: str,
                       **datos_especificos: Any) -> Cita:
        paciente = self.pacientes.obtener(id_paciente)
        profesional = self.profesionales.obtener(id_profesional)
        if paciente is None:
            raise ValueError("No existe el paciente indicado.")
        if profesional is None:
            raise ValueError("No existe el profesional indicado.")
        cita = FabricaCitas.crear_cita(
            tipo,
            id_cita=id_cita,
            paciente=paciente,
            profesional=profesional,
            fecha=fecha,
            motivo=motivo,
            **datos_especificos,
        )
        fin = cita.fecha_fin
        if not profesional.esta_disponible(cita.fecha, fin):
            raise ValueError("El profesional no está disponible en ese horario.")
        if self._hay_solapamiento(cita, self.citas.listar()):
            raise ValueError("La cita se superpone con otra cita del paciente o profesional.")
        cita.programar()
        self.citas.guardar(cita)
        return cita

    def cancelar_cita(self, id_cita: str) -> None:
        cita = self.citas.obtener(id_cita)
        if cita is None:
            raise ValueError("No existe la cita indicada.")
        cita.cancelar()

    def reprogramar_cita(self, id_cita: str, nueva_fecha: datetime) -> Cita:
        cita = self.citas.obtener(id_cita)
        if cita is None:
            raise ValueError("No existe la cita indicada.")
        # Valida con una copia temporal para no mutar la cita antes de pasar reglas.
        cita_temporal = FabricaCitas.crear_cita(
            cita.tipo,
            id_cita=f"TEMP-{cita.id_cita}",
            paciente=cita.paciente,
            profesional=cita.profesional,
            fecha=nueva_fecha,
            motivo=cita.motivo,
            **({"tipo_consulta": cita.tipo_consulta} if isinstance(cita, CitaGeneral) else {
                "diagnostico_previo": cita.diagnostico_previo,
                "proximo_control": cita.proximo_control,
            }),
        )
        if not cita.profesional.esta_disponible(cita_temporal.fecha, cita_temporal.fecha_fin):
            raise ValueError("El profesional no está disponible en el nuevo horario.")
        if self._hay_solapamiento(cita_temporal, self.citas.listar(), excluir_id=cita.id_cita):
            raise ValueError("La nueva fecha se superpone con otra cita.")
        cita.reprogramar(nueva_fecha)
        return cita

    def registrar_atencion(self, id_cita: str, diagnostico: str,
                           observaciones: str = "",
                           fecha_atencion: Optional[datetime] = None) -> Atencion:
        cita = self.citas.obtener(id_cita)
        if cita is None:
            raise ValueError("No existe la cita indicada.")
        if cita.estado != EstadoCita.PROGRAMADA:
            raise ValueError("Solo una cita programada puede convertirse en atención.")
        siguiente = len(self.atenciones.listar()) + 1
        atencion = cita.profesional.registrar_atencion(
            cita, f"A-{siguiente:04d}", diagnostico, observaciones, fecha_atencion
        )
        # Validaciones anteriores han pasado: registrar las dos entidades vinculadas.
        atencion.registrar()
        self.atenciones.guardar(atencion)
        cita.completar()
        cita.paciente._agregar_atencion(atencion)
        return atencion

    def crear_receta(self, id_atencion: str, id_receta: str,
                     indicaciones: str) -> Receta:
        atencion = self.atenciones.obtener(id_atencion)
        if atencion is None:
            raise ValueError("No existe la atención indicada.")
        receta = atencion.generar_receta(id_receta, indicaciones)
        self.recetas.guardar(receta)
        return receta

    def emitir_receta(self, id_receta: str) -> Receta:
        receta = self.recetas.obtener(id_receta)
        if receta is None:
            raise ValueError("No existe la receta indicada.")
        receta.validar()
        receta.emitir()
        return receta

    def generar_reporte_citas(self, fecha: Optional[date] = None) -> Reporte:
        return self.reportes.reporte_citas(fecha)

    def generar_reporte_atenciones(self) -> Reporte:
        return self.reportes.reporte_atenciones()

    def generar_reporte_inventario(self) -> Reporte:
        return self.reportes.reporte_inventario()


# ================================================================
# 11. DEMOSTRACIÓN DEL FLUJO COMPLETO
# ================================================================

def ejecutar_demo() -> None:
    print("=" * 76)
    print("SistemaRural-PE | Demostración académica del diagrama UML")
    print("=" * 76)
    sistema = ServicioSalud()

    # Cuenta del personal (contraseña ficticia; nunca se imprime).
    usuario = Usuario("U-001", "Operador Demo", "operador@example.org", "ClaveDemo2026", "administrador")
    sistema.registrar_usuario(usuario)
    print("Usuario autenticado:", usuario.autenticar("ClaveDemo2026"))
    usuario.cerrar_sesion()

    paciente = Paciente("P-0001", "00000001", "Paciente", "Demostración",
                        date(1990, 5, 15), "No especificado", "900000000", "Localidad rural")
    sistema.registrar_paciente(paciente)

    medico = Medico("PS-001", "Ana", "Médica Demo", "Medicina general", "CMP-DEMO-1", "CMP-12345")
    medico.actualizar_disponibilidad(datetime(2026, 11, 2, 8, 0), datetime(2026, 11, 2, 12, 0))
    sistema.registrar_profesional(medico)

    cita = sistema.programar_cita(
        tipo="general", id_cita="C-0001", id_paciente=paciente.id_paciente,
        id_profesional=medico.id_profesional, fecha=datetime(2026, 11, 2, 9, 0),
        motivo="Consulta de ejemplo", tipo_consulta="medicina general",
    )
    atencion = sistema.registrar_atencion(cita.id_cita, "Diagnóstico ficticio de demostración",
                                          "Sin datos clínicos reales.", datetime(2026, 11, 2, 9, 5))

    medicamento = Medicamento("M-001", "Medicamento de demostración", "Producto ficticio",
                              stock=25, precio=1.50, laboratorio="Laboratorio Demo")
    sistema.registrar_medicamento(medicamento)
    receta = sistema.crear_receta(atencion.id_atencion, "RX-0001", "Seguir indicación profesional ficticia.")
    receta.agregar_detalle(DetalleReceta("DR-001", medicamento, "1 unidad", "según indicación", "3 días", 3))
    sistema.emitir_receta(receta.id_receta)

    reporte = sistema.generar_reporte_citas(date(2026, 11, 2))
    print(f"Paciente registrado con código interno: {paciente.id_paciente}")
    print(f"Cita: {cita.id_cita} | tipo={cita.tipo} | estado={cita.estado.value}")
    print(f"Atención registrada: {atencion.id_atencion}")
    print(f"Receta emitida: {receta.id_receta} | unidades restantes del medicamento: {medicamento.stock}")
    print("Reporte agregado:", dict(reporte.datos))
    print("\nNota: la demostración utiliza datos ficticios y almacenamiento en memoria.\n")


# ================================================================
# 12. PRUEBAS AUTOMATIZADAS
# ================================================================

class TestSistemaRuralPE(unittest.TestCase):
    def setUp(self) -> None:
        self.sistema = ServicioSalud()
        self.paciente = Paciente("P-0001", "00000001", "Nombre", "Ficticio",
                                 date(1990, 1, 1), "No especificado")
        self.sistema.registrar_paciente(self.paciente)
        self.medico = Medico("PS-001", "Médico", "Prueba", "Medicina general", "CMP-T-1", "CMP-0001")
        self.sistema.registrar_profesional(self.medico)
        self.fecha = datetime(2026, 11, 2, 9, 0)

    def crear_cita_general(self) -> Cita:
        return self.sistema.programar_cita(
            tipo="general", id_cita="C-0001", id_paciente=self.paciente.id_paciente,
            id_profesional=self.medico.id_profesional, fecha=self.fecha,
            motivo="Prueba unitaria", tipo_consulta="consulta general",
        )

    def test_factory_crea_subtipo_correcto(self) -> None:
        general = FabricaCitas.crear_cita(
            "general", id_cita="T-1", paciente=self.paciente, profesional=self.medico,
            fecha=self.fecha, motivo="Test", tipo_consulta="general",
        )
        control = FabricaCitas.crear_cita(
            "control", id_cita="T-2", paciente=self.paciente, profesional=self.medico,
            fecha=self.fecha, motivo="Test", diagnostico_previo="Diagnóstico de prueba",
        )
        self.assertIsInstance(general, CitaGeneral)
        self.assertIsInstance(control, CitaControl)
        self.assertEqual(general.duracion_minutos, 30)
        self.assertEqual(control.duracion_minutos, 20)

    def test_no_permite_solapamiento(self) -> None:
        self.crear_cita_general()
        with self.assertRaisesRegex(ValueError, "superpone"):
            self.sistema.programar_cita(
                tipo="control", id_cita="C-0002", id_paciente="P-0001",
                id_profesional="PS-001", fecha=datetime(2026, 11, 2, 9, 10),
                motivo="Control", diagnostico_previo="Previo",
            )

    def test_atencion_completa_cita_y_aparece_en_historial(self) -> None:
        cita = self.crear_cita_general()
        atencion = self.sistema.registrar_atencion(cita.id_cita, "Diagnóstico ficticio", "Observación ficticia", self.fecha)
        self.assertEqual(cita.estado, EstadoCita.COMPLETADA)
        self.assertTrue(atencion.registrada)
        self.assertEqual(len(self.paciente.obtener_historial()), 1)

    def test_emitir_receta_descuenta_stock_una_vez(self) -> None:
        cita = self.crear_cita_general()
        atencion = self.sistema.registrar_atencion(cita.id_cita, "Diagnóstico ficticio", fecha_atencion=self.fecha)
        medicamento = Medicamento("M-001", "Medicamento test", "Ficticio", 10, 2.0, "Lab test")
        self.sistema.registrar_medicamento(medicamento)
        receta = self.sistema.crear_receta(atencion.id_atencion, "RX-1", "Indicaciones ficticias")
        receta.agregar_detalle(DetalleReceta("D-1", medicamento, "1 unidad", "cada día", "3 días", 3))
        self.sistema.emitir_receta("RX-1")
        self.assertEqual(medicamento.stock, 7)
        self.assertEqual(receta.estado, EstadoReceta.EMITIDA)
        with self.assertRaises(ValueError):
            receta.emitir()

    def test_receta_no_emite_si_no_hay_stock(self) -> None:
        cita = self.crear_cita_general()
        atencion = self.sistema.registrar_atencion(cita.id_cita, "Diagnóstico ficticio", fecha_atencion=self.fecha)
        medicamento = Medicamento("M-002", "Medicamento sin stock", "Ficticio", 1, 2.0, "Lab test")
        self.sistema.registrar_medicamento(medicamento)
        receta = self.sistema.crear_receta(atencion.id_atencion, "RX-2", "Indicaciones ficticias")
        receta.agregar_detalle(DetalleReceta("D-2", medicamento, "1 unidad", "cada día", "3 días", 2))
        with self.assertRaisesRegex(ValueError, "Stock insuficiente"):
            receta.validar()
        self.assertEqual(medicamento.stock, 1)

    def test_reporte_no_incluye_datos_personales(self) -> None:
        self.crear_cita_general()
        reporte = self.sistema.generar_reporte_citas(date(2026, 11, 2))
        texto = json.dumps(dict(reporte.datos), ensure_ascii=False)
        self.assertEqual(reporte.datos["total_citas"], 1)
        self.assertNotIn(self.paciente.dni, texto)
        self.assertNotIn(self.paciente.nombres, texto)

    def test_singleton_reutiliza_misma_instancia(self) -> None:
        primera = ConfiguracionSistema.obtener_instancia()
        segunda = ConfiguracionSistema()
        self.assertIs(primera, segunda)

    def test_autenticacion_y_cambio_de_contrasena(self) -> None:
        usuario = Usuario("U-1", "Operador", "op@example.org", "ClaveInicial1", "operador")
        self.assertTrue(usuario.autenticar("ClaveInicial1"))
        usuario.cambiar_contrasena("ClaveInicial1", "ClaveNueva22")
        self.assertFalse(usuario.autenticar("ClaveInicial1"))
        self.assertTrue(usuario.autenticar("ClaveNueva22"))

    def test_enfermera_registra_signos_vitales(self) -> None:
        cita = self.crear_cita_general()
        atencion = self.sistema.registrar_atencion(cita.id_cita, "Diagnóstico ficticio", fecha_atencion=self.fecha)
        enfermera = Enfermera("PS-002", "Enfermera", "Prueba", "Enfermería", "COL-E-1", "ENF-01")
        signos = enfermera.registrar_signos_vitales(
            atencion, temperatura_c=36.5, frecuencia_cardiaca=75,
            presion_arterial="120/80", frecuencia_respiratoria=16,
            saturacion_oxigeno=98,
        )
        self.assertEqual(signos["temperatura_c"], 36.5)
        self.assertIn("presion_arterial", atencion.signos_vitales)


if __name__ == "__main__":
    ejecutar_demo()
    print("EJECUTANDO PRUEBAS AUTOMATIZADAS...\n")
    unittest.main(argv=["sistema_rural_pe.py"], verbosity=2, exit=False)
