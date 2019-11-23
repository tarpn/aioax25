#!/usr/bin/env python3

from aioax25.frame import AX25Frame, AX25RawFrame, \
        AX25UnnumberedInformationFrame, AX258BitReceiveReadyFrame, \
        AX2516BitReceiveReadyFrame, AX258BitRejectFrame, \
        AX2516BitRejectFrame

from nose.tools import eq_
from ..hex import from_hex, hex_cmp

# Basic frame operations

def test_decode_incomplete():
    """
    Test that an incomplete frame does not cause a crash.
    """
    try:
        AX25Frame.decode(
                from_hex(
                    'ac 96 68 84 ae 92 e0'      # Destination
                    'ac 96 68 9a a6 98 61'      # Source
                )
        )
        assert False, 'This should not have worked'
    except ValueError as e:
        eq_(str(e), 'Insufficient packet data')

def test_decode_iframe():
    """
    Test that an I-frame gets decoded to a raw frame.
    """
    frame = AX25Frame.decode(
            from_hex(
                'ac 96 68 84 ae 92 e0'      # Destination
                'ac 96 68 9a a6 98 61'      # Source
                '00 11 22 33 44 55 66 77'   # Payload
            )
    )
    assert isinstance(frame, AX25RawFrame), 'Did not decode to raw frame'
    hex_cmp(frame.frame_payload, '00 11 22 33 44 55 66 77')

def test_decode_sframe():
    """
    Test that an S-frame gets decoded to a raw frame.
    """
    frame = AX25Frame.decode(
            from_hex(
                'ac 96 68 84 ae 92 e0'      # Destination
                'ac 96 68 9a a6 98 61'      # Source
                '01 11 22 33 44 55 66 77'   # Payload
            )
    )
    assert isinstance(frame, AX25RawFrame), 'Did not decode to raw frame'
    hex_cmp(frame.frame_payload, '01 11 22 33 44 55 66 77')

def test_decode_rawframe():
    """
    Test that we can decode an AX25RawFrame.
    """
    rawframe = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            cr=True,
            payload=b'\x03\xf0This is a test'
    )
    frame = AX25Frame.decode(rawframe)
    assert isinstance(frame, AX25UnnumberedInformationFrame)
    eq_(frame.pid, 0xf0)
    eq_(frame.payload, b'This is a test')

def test_frame_timestamp():
    """
    Test that the timestamp property is set from constructor.
    """
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            timestamp=11223344
    )
    eq_(frame.timestamp, 11223344)

def test_frame_deadline():
    """
    Test that the deadline property is set from constructor.
    """
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            deadline=11223344
    )
    eq_(frame.deadline, 11223344)

def test_frame_deadline_ro_if_set_constructor():
    """
    Test that the deadline property is read-only once set by contructor
    """
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            deadline=11223344
    )
    try:
        frame.deadline = 99887766
    except ValueError as e:
        eq_(str(e), 'Deadline may not be changed after being set')

    eq_(frame.deadline, 11223344)

def test_frame_deadline_ro_if_set():
    """
    Test that the deadline property is read-only once set after constructor
    """
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
    )

    frame.deadline=44556677

    try:
        frame.deadline = 99887766
    except ValueError as e:
        eq_(str(e), 'Deadline may not be changed after being set')

    eq_(frame.deadline, 44556677)

def test_encode_raw():
    """
    Test that we can encode a raw frame.
    """
    # Yes, this is really a UI frame.
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            cr=True,
            payload=b'\x03\xf0This is a test'
    )
    hex_cmp(bytes(frame),
            'ac 96 68 84 ae 92 e0'                          # Destination
            'ac 96 68 9a a6 98 61'                          # Source
            '03'                                            # Control
            'f0 54 68 69 73 20 69 73 20 61 20 74 65 73 74'  # Payload
    )

def test_raw_copy():
    """
    Test we can make a copy of a raw frame.
    """
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            payload=b'\xabThis is a test'
    )
    framecopy = frame.copy()
    assert framecopy is not frame

    hex_cmp(bytes(framecopy),
            'ac 96 68 84 ae 92 60'                          # Destination
            'ac 96 68 9a a6 98 e1'                          # Source
            'ab'                                            # Control
            '54 68 69 73 20 69 73 20 61 20 74 65 73 74'     # Payload
    )

def test_raw_str():
    """
    Test we can get a string representation of a raw frame.
    """
    frame = AX25RawFrame(
            destination='VK4BWI',
            source='VK4MSL',
            payload=b'\xabThis is a test'
    )
    eq_(str(frame), "VK4MSL>VK4BWI")
