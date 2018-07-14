import io
import struct
from uuid import uuid4

import crcmod


class ParseError(Exception):
    """There was an error during parsing"""

    def __init__(self, data, fmt):
        self.data = data
        self.fmt = fmt

    def __str__(self):
        return 'ParseError: fmt="{s.fmt}" data={s.data}'.format(s=self)


def _unpack(stream, length, fmt):
    """Unpack data from a stream and raise a nicely formatted exception if required"""
    data = stream.read(length)
    try:
        if not len(data) == length:
            raise ValueError(
                "Data too short, saw {} expected {}".format(len(data), length)
            )
        unpacked = struct.unpack(fmt, data)
        if len(unpacked) == 1:
            return unpacked[0]
        else:
            return unpacked
    except Exception as exc:
        raise ParseError(data, fmt) from exc


def _get_bits(value, mask):
    shift = 0
    while not ((mask >> shift) & 0x1):
        shift += 1
    return (value & mask) >> shift


def _set_bits(value, mask, bits):
    shift = 0
    while not ((mask >> shift) & 0x1):
        shift += 1
    return (value & (~mask)) | ((bits << shift) & mask)


class Struct(object):
    """
    Represents some data object that can parse data and be built back into a binary stream.
    """

    @classmethod
    def parse(cls, stream):
        """
        Read the stream and parse data into an instance of the class.
        """
        raise NotImplementedError()

    def build(self):
        """
        Pack the instance into a `bytes` object
        """
        raise NotImplementedError()

    _repr_attrs = ()

    def __repr__(self):
        """Create a __repr__ string for an object"""
        values = ((name, getattr(self, name)) for name in self._repr_attrs)
        kw = ", ".join("{}={}".format(k, v) for k, v in values)
        return "{cls}({kw})".format(cls=self.__class__.__name__, kw=kw)

    __str__ = __repr__


class Header(Struct):
    """
    EEPROM Header

    Bytes   Field
    4       signature   signature: 0x52, 0x2D, 0x50, 0x69 ("R-Pi" in ASCII)
    1       version     EEPROM data format version (0x00 reserved, 0x01 = first version)
    1       reserved    set to 0
    2       numatoms    total atoms in EEPROM
    4       eeplen      total length in bytes of all eeprom data (including this header)
    """

    _repr_attrs = ("signature", "version", "numatoms", "eeplen")

    def __init__(self, signature=b"R-Pi", version=0x1, numatoms=0, eeplen=0):
        self.signature = signature
        self.version = version
        self.numatoms = numatoms
        self.eeplen = eeplen

    @classmethod
    def parse(cls, stream):
        signature, version, _, numatoms, eeplen = _unpack(stream, 12, "<4sBBHI")
        return cls(signature, version, numatoms, eeplen)

    def build(self):
        return struct.pack(
            "<4sBBHI", self.signature, self.version, 0, self.numatoms, self.eeplen
        )


class VendorInfoAtomData(Struct):
    """
    Vendor Info Atom Data

    Bytes   Field
    16      uuid        UUID (unique for every single board ever made)
    2       pid         product ID
    2       pver        product version
    1       vslen       vendor string length (bytes)
    1       pslen       product string length (bytes)
    X       vstr        ASCII vendor string e.g. "ACME Technology Company"
    Y       pstr        ASCII product string e.g. "Special Sensor Board"
    """

    _repr_attrs = (
        "uuid",
        "product_id",
        "product_version",
        "vendor_string",
        "product_string",
    )

    def __init__(
        self,
        uuid=None,
        product_id=0,
        product_version=0,
        vendor_string=b"",
        product_string=b"",
        vendor_slen=0,
        product_slen=0,
    ):
        if uuid is None:
            self.uuid = uuid4().bytes_le
        else:
            self.uuid = uuid
        self.product_id = product_id
        self.product_version = product_version
        self.vendor_slen = vendor_slen
        self.product_slen = product_slen
        self.vendor_string = vendor_string
        self.product_string = product_string

    @classmethod
    def parse(cls, stream, length=None):
        uuid, pid, pver, vslen, pslen = _unpack(stream, 22, "<16sHHBB")
        vstr = _unpack(stream, vslen, "{}s".format(vslen))
        pstr = _unpack(stream, pslen, "{}s".format(pslen))
        return cls(
            uuid=uuid,
            product_id=pid,
            product_version=pver,
            vendor_string=vstr,
            product_string=pstr,
            vendor_slen=vslen,
            product_slen=pslen,
        )

    def build(self):
        self.vendor_slen = len(self.vendor_string)
        self.product_slen = len(self.product_string)
        return struct.pack(
            "<16sHHBB{vslen}s{pslen}s".format(
                vslen=self.vendor_slen, pslen=self.product_slen
            ),
            self.uuid,
            self.product_id,
            self.product_version,
            self.vendor_slen,
            self.product_slen,
            self.vendor_string,
            self.product_string,
        )


def _make_bitfield_property(attrname, bits, value_map):
    value_map_rev = {v: k for k, v in value_map.items()}  # reversed

    def _get(self):
        attr = getattr(self, attrname)
        val = _get_bits(attr, bits)
        if not val in value_map_rev:
            raise KeyError("invalid value: {}".format(val))
        return value_map_rev[val]

    def _set(self, value):
        attr = getattr(self, attrname)
        if value not in value_map:
            raise KeyError("invalid value: {}".format(value))
        new_value = _set_bits(attr, bits, value_map[value])
        setattr(self, attrname, new_value)

    return property(_get, _set)


class GPIOPin(Struct):
    """
    GPIO Pin

    Attributes are mapped to meaningful values.  Get or set attributes with this value.

    `func_sel` can have the following values:

      - `input`
      - `output`
      - `alt0`
      - `alt1`
      - `alt2`
      - `alt3`
      - `alt4`
      - `alt5`

    `pulltype` can have the following values:

      - `default`
      - `pullup`
      - `pulldown`
      - `nopull`

    `is_used` can have the following values:

      - `False`
      - `True`

    """

    _repr_attrs = ("func_sel", "pulltype", "is_used")

    def __init__(self, data):
        self.data = data

    @classmethod
    def parse(cls, stream):
        data = _unpack(stream, 1, "<B")
        return cls(data)

    def build(self):
        return self.data.to_bytes(1, "little")

    func_sel = _make_bitfield_property(
        "data",
        0x03,
        {
            "input": 0,
            "output": 1,
            "alt0": 4,
            "alt1": 5,
            "alt2": 6,
            "alt3": 7,
            "alt4": 3,
            "alt5": 2,
        },
    )

    pulltype = _make_bitfield_property(
        "data", 0x60, {"default": 0, "pullup": 1, "pulldown": 2, "nopull": 3}
    )

    is_used = _make_bitfield_property("data", 0x80, {False: 0, True: 1})


class GPIOMapAtomData(Struct):
    """
    GPIO Map Atom Data

    Attributes are mapped to meaningful values.  Get or set attributes with this value.

    `drive` can have the following values:

      - `default`
      -  integer 1-8

    `slew` can have the following values:

      - `default`
      - `enabled`
      - `disabled`

   `hysteresis` can have the following values:

      - `default`
      - `enabled`
      - `disabled`

   `back_power` can have the following values:

      - `disabled`
      - `enabled_1.3A`
      - `enabled_2A`

    """

    _repr_attrs = ("drive", "slew", "hysteresis", "back_power", "pins")

    def __init__(self, bank_drive=0, power=0, pins=None):
        self.bank_drive = bank_drive
        self.power = power
        if pins is None:
            self.pins = [GPIOPin(0) for _ in range(28)]
        else:
            self.pins = pins

    drive = _make_bitfield_property(
        "bank_drive", 0x0f, {"default": 0, **{n: n for n in range(1, 9)}}
    )

    slew = _make_bitfield_property(
        "bank_drive", 0x30, {"default": 0, "enabled": 1, "disabled": 2}
    )

    hysteresis = _make_bitfield_property(
        "bank_drive", 0xc0, {"default": 0, "enabled": 1, "disabled": 2}
    )

    back_power = _make_bitfield_property(
        "power", 0x03, {"disabled": 0, "enabled_1.3A": 1, "enabled_2A": 2}
    )

    @classmethod
    def parse(cls, stream, length=None):
        bank_drive, power = _unpack(stream, 2, "<BB")
        return cls(bank_drive, power, [GPIOPin.parse(stream) for _ in range(28)])

    def build(self):
        pins = b"".join(p.build() for p in self.pins)
        return struct.pack("<BB28s", self.bank_drive, self.power, pins)


class DeviceTreeAtomData(Struct):
    """
    Device Tree Atom Data

    Format is just a blob.
    """

    _repr_attrs = ("blob",)

    def __init__(self, blob):
        self.blob = blob

    @classmethod
    def parse(cls, stream, length):
        blob = _unpack(stream, length, "<{}s".format(length))
        return cls(blob)

    def build(self):
        return struct.pack("<{}s".format(len(self.blob)), self.blob)


class CustomDataAtomData(Struct):
    """
    Custom Atom Data

    Format is just a blob.
    """

    _repr_attrs = ("blob",)

    def __init__(self, blob):
        self.blob = blob

    @classmethod
    def parse(cls, stream, length):
        blob = _unpack(stream, length, "<{}s".format(length))
        return cls(blob)

    def build(self):
        return struct.pack("<{}s".format(len(self.blob)), self.blob)


class Atom(Struct):
    """
    Atom

    Bytes   Field
    2       type        atom type
    2       count       incrementing atom count
    4       dlen        length in bytes of data+CRC
    N       data        N bytes, N = dlen-2
    2       crc16       CRC-16-CCITT of entire atom (type, count, dlen, data)
    """

    _repr_attrs = ("type_name", "data", "crc")

    atom_types = {
        0x1: ("vendor_info", VendorInfoAtomData),
        0x2: ("gpio_map", GPIOMapAtomData),
        0x3: ("devicetree", DeviceTreeAtomData),
        0x4: ("custom_data", CustomDataAtomData),
    }

    def __init__(self, type, count, dlen, data, crc=0):
        self.type = type
        self.count = count
        self.dlen = dlen
        self.data = data  #: data may be an object (VendorInfoAtomData) or bytes
        self.crc = crc

    @property
    def type_name(self):
        """
        The string name of the type of atom.
        """
        return self.atom_types.get(self.type, (None, None))[0]

    @property
    def _data_raw(self):
        if hasattr(self.data, "build"):
            return self.data.build()
        else:
            return self.data

    @classmethod
    def parse(cls, stream, length=None):
        # First, unpack up to data length
        type_, count, dlen = _unpack(stream, 8, "<HHI")

        # If possible, get a specific class for the atom data and let that
        # class parse the data.
        type_class = cls.atom_types.get(type_, (None, None))[1]
        if type_class is not None:
            # atom data classes might need to know how much to parse
            data = type_class.parse(stream, length=dlen - 2)
        else:
            # don't know the class, so data is plain bytes
            data = _unpack(stream, dlen - 2, "{dlen}s".format(dlen=dlen - 2))

        # Finish up
        crc = _unpack(stream, 2, "H")
        return cls(type_, count, dlen, data, crc)

    def build(self):
        data_raw = self._data_raw
        self.dlen = len(data_raw) + 2  # includes CRC
        data = struct.pack(
            "<HHI{dlen}s".format(dlen=self.dlen - 2),
            self.type,
            self.count,
            self.dlen,
            data_raw,
        )
        crc_func = crcmod.predefined.mkCrcFun("crc-16")
        self.crc = crc_func(data)
        return struct.pack("<{}sH".format(len(data)), data, self.crc)


class EEPROM(Struct):
    """
    EEPROM

    Bytes   Field
    12      Header
    N       Atoms
    """

    _repr_attrs = ("header", "atoms")

    def __init__(self, header=None, atoms=None):
        if header is not None:
            self.header = header
        else:
            self.header = Header()
        if atoms is not None:
            self.atoms = atoms
        else:
            self.atoms = []

    @classmethod
    def parse(cls, data):
        """
        Load binary data to create an EEPROM
        """
        stream = io.BytesIO(data)
        header = Header.parse(stream)
        atoms = []
        for numatom in range(header.numatoms):
            atoms.append(Atom.parse(stream))
        header.numatoms = numatom
        return cls(header, atoms)

    def update(self):
        for count, atom in enumerate(self.atoms):
            atom.count = count
            # build each atom to update its size
            atom.build()
        self.header.numatoms = count + 1
        # build (but don't update!) to recalculate the total size
        build = self.build(update=False)
        self.header.eeplen = len(build)

    def build(self, update=True):
        """
        Build a binary representation of the EEPROM.
        """
        if update:
            self.update()
        stream = io.BytesIO()
        stream.write(self.header.build())
        for atom in self.atoms:
            stream.write(atom.build())
        return stream.getvalue()

    @classmethod
    def create(cls, **kw):
        """
        Create an EEPROM from scratch.

        This creates 'vendor_info' and 'gpio_map' atoms by default.
        """
        inst = cls()
        inst.add_atom("vendor_info")
        inst.add_atom("gpio_map")
        inst.update()
        return inst

    @property
    def atoms_type(self):
        """
        Dictionary of atoms by type string name.
        """
        return {a.type_name: a for a in self.atoms}

    def add_atom(self, name, *args, **kwargs):
        """
        Add an atom to the EEPROM by type name.  Args are passed to the data class.
        """
        for type_val, (type_name, type_cls) in Atom.atom_types.items():
            if type_name == name:
                break
        else:
            raise KeyError(type_name)
        data = type_cls(*args, **kwargs)
        data_build = data.build()
        atom = Atom(type_val, len(self.atoms), len(data_build), data)
        self.atoms.append(atom)
        self.update()
        return atom


if __name__ == "__main__":
    with open("eeprom.bin", "rb") as f:
        eep = EEPROM.parse(f.read())

    eep.atoms_type["vendor_info"].data.vendor_string = b"foo"
    if not "custom_data" in eep.atoms_type:
        eep.add_atom("custom_data", b"hello world")
    eep.update()
    with open("eeprom_new.bin", "wb") as f:
        f.write(eep.build())

    # eep = EEPROM.create()
    # print(eep)
