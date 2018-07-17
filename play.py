import collections
import struct

class _Context(collections.UserDict):
    def __init__(self, struct_obj):
        self.obj = struct_obj

class Field(object):
    def __init__(self, fmt):
        self._fmt = fmt
        self._converter = None
        self._ctx = None

    def __get__(self, obj, type=None):
        return self._value

    def __set__(self, obj, value):
        if self._converter:
            self._raw = self._converter(self, obj, value)
        else:
            self._raw = value

    @property
    def fmt(self):
        if callable(self._fmt):
            return self._fmt(self._ctx)
        else:
            return self._fmt

    def _parse(self, stream):
        fmt = self.fmt(ctx)
        size struct.calcsize(self.fmt(ctx))
        read = stream.read(size)
        data = struct.unpack(fmt, read)
        if self._parser is not None:
            self._value = self._parser(data, ctx)

    def _build(self, stream, ctx):
        pass

    def parser(self, f):
        self._parser = f

    def builder(self, f):
        self._builder = f


class Struct(object):
    pass

class AtomData(Struct):
    type = Field(
        'H',
        parse_map={
            0x0001: 'vendor_info',
            0x0002: 'gpio_map',
        }
    )
    count = Field('H')
    dlen = Field('I')
    data = Field(
        lambda ctx: '{}s'.format(ctx['dlen'] - 2),
        parse_map={
            'vendor_info': VendorInfoAtomData,
        )
    )
    crc = Field('H')

    @type.parser
    def type(data, ctx):
        types = {
        }
        return types.get(data, default=data)

    @data.parser
    def data(data, ctx):
        types = {
        }
        return types.get(ctx.obj.type, default=data)

    def _build(self, stream):
        val = self._values
        val['dlen'] = len(val['data'])
        crc_data = b''.join((
            val['type'],
            val['count'],
            val['dlen'],
            val['data']
        ))
        val['crc'] = crc_data
        return super()._build()
