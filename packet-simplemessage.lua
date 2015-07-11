--[[
  Routines for ROS-Industrial SimpleMessage dissection
  Copyright (c) 2013-2015, G.A. vd. Hoorn, TU Delft Robotics Institute
  All rights reserved.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

  ---

  Wireshark dissector in Lua for the ROS-Industrial SimpleMessage protocol.
  For more information on the protocol, see [1].

  Written for the 'groovy' version of the SimpleMessage protocol.

  Tested on Wireshark 1.9.0-SVN-46273 on Windows.

  Known issues and open feature requests, see [2].


  Author: G.A. vd. Hoorn, TU Delft Robotics Institute

  [1] http://ros.org/wiki/simple_message
  [2] https://github.com/ros-industrial/packet-simplemessage/issues
]]
do

	--
	-- constants
	--
	local DISSECTOR_VERSION              = "0.1.9"

	local MIN_PKT_LEN                    = 44

	local MSG_PING                       = 0x01
	local MSG_JOINT_POSITION             = 0x0A
	local MSG_JOINT_TRAJ_PT              = 0x0B
	local MSG_JOINT_TRAJ                 = 0x0C
	local MSG_STATUS                     = 0x0D
	local MSG_JOINT_TRAJ_PT_FULL         = 0x0E
	local MSG_JOINT_FEEDBACK             = 0x0F
	local MSG_READ_INPUT                 = 0x14
	local MSG_WRITE_OUTPUT               = 0x15

	local MSG_MOTO_BEGIN                 = 0x7D0
	local MSG_MOTO_MOTION_CTRL           = 0x7D1
	local MSG_MOTO_MOTION_REPLY          = 0x7D2
	local MSG_MOTO_JOINT_TRAJ_PT_FULL_EX = 0x7E0
	local MSG_MOTO_JOINT_FEEDBACK_EX     = 0x7E1

	local COMM_INVALID                   = 0x00
	local COMM_TOPIC                     = 0x01
	local COMM_SERVICE_REQUEST           = 0x02
	local COMM_SERVICE_REPL              = 0x03

	local REPLY_INVALID                  = 0x00
	local REPLY_SUCCESS                  = 0x01
	local REPLY_FAILURE                  = 0x02

	local START_TRAJECTORY_DOWNLOAD      = -1
	local START_TRAJECOTRY_STREAMING     = -2
	local END_TRAJECTORY                 = -3
	local STOP_TRAJECTORY                = -4

	local VALID_FIELD_TYPE_TIME          = 0x01
	local VALID_FIELD_TYPE_POSITION      = 0x02
	local VALID_FIELD_TYPE_VELOCITY      = 0x04
	local VALID_FIELD_TYPE_ACCELERATION  = 0x08

	local STATUS_ROBOTMODE_UNKNOWN       = -1
	local STATUS_ROBOTMODE_MANUAL        =  1
	local STATUS_ROBOTMODE_AUTO          =  2

	local STATUS_TRISTATE_UNKNOWN        = -1
	local STATUS_TRISTATE_OFF            =  0
	local STATUS_TRISTATE_FALSE          =  0
	local STATUS_TRISTATE_ON             =  1
	local STATUS_TRISTATE_TRUE           =  1


	local MOTO_MOTION_CTRL_CMD_UNDEFINED                      = 0
	local MOTO_MOTION_CTRL_CMD_JOINT_TRAJ_PT_FULL             = MSG_JOINT_TRAJ_PT_FULL
	local MOTO_MOTION_CTRL_CMD_JOINT_TRAJ_PT_FULL_EX          = MSG_MOTO_JOINT_TRAJ_PT_FULL_EX
	local MOTO_MOTION_CTRL_CMD_CHECK_MOTION_READY             = 200101
	local MOTO_MOTION_CTRL_CMD_CHECK_QUEUE_CNT                = 200102
	local MOTO_MOTION_CTRL_CMD_STOP_MOTION                    = 200111
	local MOTO_MOTION_CTRL_CMD_START_TRAJ_MODE                = 200121
	local MOTO_MOTION_CTRL_CMD_STOP_TRAJ_MODE                 = 200122

	local MOTO_MOTION_REPLY_RESULT_SUCCESS                    = 0
	local MOTO_MOTION_REPLY_RESULT_TRUE                       = 0
	local MOTO_MOTION_REPLY_RESULT_BUSY                       = 1
	local MOTO_MOTION_REPLY_RESULT_FAILURE                    = 2
	local MOTO_MOTION_REPLY_RESULT_FALSE                      = 2
	local MOTO_MOTION_REPLY_RESULT_INVALID                    = 3
	local MOTO_MOTION_REPLY_RESULT_ALARM                      = 4
	local MOTO_MOTION_REPLY_RESULT_NOT_READY                  = 5
	local MOTO_MOTION_REPLY_RESULT_MP_FAILURE                 = 6

	local MOTO_MOTION_REPLY_SUBCODE_INVALID_UNSPECIFIED       = 3000
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_MSGSIZE           = 3001
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_MSGHEADER         = 3002
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_MSGTYPE           = 3003
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_GROUPNO           = 3004
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_SEQUENCE          = 3005
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_COMMAND           = 3006
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA              = 3010
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_START_POS    = 3011
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_POSITION     = 3012
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_SPEED        = 3013
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_ACCEL        = 3013
	local MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_INSUFFICIENT = 3014

	local MOTO_MOTION_REPLY_NOTREADY_CODE_UNSPECIFIED         = 5000
	local MOTO_MOTION_REPLY_NOTREADY_CODE_ALARM               = 5001
	local MOTO_MOTION_REPLY_NOTREADY_CODE_ERROR               = 5002
	local MOTO_MOTION_REPLY_NOTREADY_CODE_ESTOP               = 5003
	local MOTO_MOTION_REPLY_NOTREADY_CODE_NOT_PLAY            = 5004
	local MOTO_MOTION_REPLY_NOTREADY_CODE_NOT_REMOTE          = 5005
	local MOTO_MOTION_REPLY_NOTREADY_CODE_SERVO_OFF           = 5006
	local MOTO_MOTION_REPLY_NOTREADY_CODE_HOLD                = 5007
	local MOTO_MOTION_REPLY_NOTREADY_CODE_NOT_STARTED         = 5008
	local MOTO_MOTION_REPLY_NOTREADY_CODE_WAITING_ROS         = 5009






	--
	-- misc
	--

	-- cache globals to local for speed
	local _F = string.format

	-- wireshark API globals
	local Pref = Pref

	-- minimal config
	local config = {
		target_be = true,
		autodetect_endianness = true,
		display_invalid_fields = true
	}






	--
	-- constant -> string rep tables
	--

	local set_not_set_str = {
		[0] = "Not set",
		[1] = "Set"
	}

	local in_valid_str = {
		[0] = "Invalid",
		[1] = "Valid"
	}

	local pkt_types_str = {
		[MSG_PING                      ] = "Ping",
		[MSG_JOINT_POSITION            ] = "Joint Position",
		[MSG_JOINT_TRAJ_PT             ] = "Joint Trajectory Point",
		[MSG_JOINT_TRAJ                ] = "Joint Trajectory",
		[MSG_STATUS                    ] = "Status",
		[MSG_JOINT_TRAJ_PT_FULL        ] = "Joint Trajectory Point Full",
		[MSG_JOINT_FEEDBACK            ] = "Joint Feedback",
		[MSG_READ_INPUT                ] = "Read Input",
		[MSG_WRITE_OUTPUT              ] = "Write Output",

		[MSG_MOTO_BEGIN                ] = "Motoman Msg Begin (BUG)",
		[MSG_MOTO_MOTION_CTRL          ] = "Motoman Motion Ctrl",
		[MSG_MOTO_MOTION_REPLY         ] = "Motoman Motion Reply",
		[MSG_MOTO_JOINT_TRAJ_PT_FULL_EX] = "Motoman Joint Trajectory Point Full Extended",
		[MSG_MOTO_JOINT_FEEDBACK_EX    ] = "Motoman Joint Feedback Extended",
		-- facilitate dissection of legacy captures (before renumbering of
		-- Motoman msgs)
		-- TODO: this will need to be removed once IDs 0x10 and 0x11 are
		--       assigned to other msgs
		[0x10                          ] = "Motoman Joint Traj. Pt Full Ext. (OLD ID)",
		[0x11                          ] = "Motoman Joint Feedback Ext. (OLD ID)",
	}

	local comm_types_str = {
		[COMM_INVALID        ] = "Unused / Invalid",
		[COMM_TOPIC          ] = "Topic",
		[COMM_SERVICE_REQUEST] = "Service Request",
		[COMM_SERVICE_REPL   ] = "Service Reply"
	}

	local reply_code_str = {
		[REPLY_INVALID] = "Unused / Invalid",
		[REPLY_SUCCESS] = "Success",
		[REPLY_FAILURE] = "Failure"
	}

	local special_seq_nr_str = {
		[START_TRAJECTORY_DOWNLOAD ] = "Start Trajectory Download",
		[START_TRAJECOTRY_STREAMING] = "Start Trajectory Streaming",
		[END_TRAJECTORY            ] = "End Trajectory",
		[STOP_TRAJECTORY           ] = "Stop Trajectory",
	}

	local valid_field_type_str = {
		[VALID_FIELD_TYPE_TIME        ] = "Time",
		[VALID_FIELD_TYPE_POSITION    ] = "Position",
		[VALID_FIELD_TYPE_VELOCITY    ] = "Velocity",
		[VALID_FIELD_TYPE_ACCELERATION] = "Acceleration"
	}

	local status_robotmode_str = {
		[STATUS_ROBOTMODE_UNKNOWN] = "Unknown",
		[STATUS_ROBOTMODE_MANUAL ] = "Manual",
		[STATUS_ROBOTMODE_AUTO   ] = "Auto"
	}

	local status_tristate_str = {
		[STATUS_TRISTATE_UNKNOWN] = "Unknown",
		[STATUS_TRISTATE_FALSE  ] = "False",
		[STATUS_TRISTATE_TRUE   ] = "True"
	}


	local motoman_ctrl_cmd_str = {
		[MOTO_MOTION_CTRL_CMD_UNDEFINED            ] = "Undefined",
		[MOTO_MOTION_CTRL_CMD_JOINT_TRAJ_PT_FULL   ] = "Joint_Traj_Pt_Full",
		[MOTO_MOTION_CTRL_CMD_JOINT_TRAJ_PT_FULL_EX] = "Joint_Traj_Pt_Full_Ex",
		[MOTO_MOTION_CTRL_CMD_CHECK_MOTION_READY   ] = "Motion Ready",
		[MOTO_MOTION_CTRL_CMD_CHECK_QUEUE_CNT      ] = "Check Queue Count",
		[MOTO_MOTION_CTRL_CMD_STOP_MOTION          ] = "Stop Motion",
		[MOTO_MOTION_CTRL_CMD_START_TRAJ_MODE      ] = "Start Traj Mode",
		[MOTO_MOTION_CTRL_CMD_STOP_TRAJ_MODE       ] = "Stop Traj Mode"
	}

	local motoman_reply_results_str = {
		[MOTO_MOTION_REPLY_RESULT_SUCCESS   ] = "Success/True",
		[MOTO_MOTION_REPLY_RESULT_BUSY      ] = "Busy",
		[MOTO_MOTION_REPLY_RESULT_FAILURE   ] = "Failure/False",
		[MOTO_MOTION_REPLY_RESULT_INVALID   ] = "Invalid",
		[MOTO_MOTION_REPLY_RESULT_ALARM     ] = "Alarm",
		[MOTO_MOTION_REPLY_RESULT_NOT_READY ] = "Not Ready",
		[MOTO_MOTION_REPLY_RESULT_MP_FAILURE] = "MP Failure"
	}

	local motoman_reply_subcodes_str = {
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_UNSPECIFIED      ] = "Unspecified",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_MSGSIZE          ] = "Message Size",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_MSGHEADER        ] = "Message Header",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_MSGTYPE          ] = "Message Type",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_GROUPNO          ] = "Group Number",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_SEQUENCE         ] = "Sequence",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_COMMAND          ] = "Command",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA             ] = "Data",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_START_POS   ] = "Data Start Pos",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_POSITION    ] = "Data Position",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_SPEED       ] = "Data Speed",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_ACCEL       ] = "Data Acceleration",
		[MOTO_MOTION_REPLY_SUBCODE_INVALID_DATA_INSUFFICIENT] = "Data Insufficient"
	}

	local motoman_not_read_code_str = {
		[MOTO_MOTION_REPLY_NOTREADY_CODE_UNSPECIFIED] = "Unspecified",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_ALARM      ] = "Alarm",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_ERROR      ] = "Error",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_ESTOP      ] = "E-Stop",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_NOT_PLAY   ] = "Not Play",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_NOT_REMOTE ] = "Not Remote",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_SERVO_OFF  ] = "Servo Off",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_HOLD       ] = "Hold",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_NOT_STARTED] = "Not Started",
		[MOTO_MOTION_REPLY_NOTREADY_CODE_WAITING_ROS] = "Waiting ROS"
	}






	--
	-- Protocol object creation and setup
	--
	local p_simplemsg_tcp = Proto("SIMPLEMESSAGE", "ROS-Industrial SimpleMessage")

	-- preferences
	p_simplemsg_tcp.prefs["version_txt"]            = Pref.statictext(_F("Dissector version: v%s", DISSECTOR_VERSION), "Shows dissector information.")
	p_simplemsg_tcp.prefs["target_be"]              = Pref.bool("Target is big-endian"  , true, "Is the target using big-endian transfers?")
	p_simplemsg_tcp.prefs["autodetect_endianness"]  = Pref.bool("Auto-detect endianness", true, "Should endianness of data be auto-detected?")
	p_simplemsg_tcp.prefs["display_invalid_fields"] = Pref.bool("Show invalid fields"   , true, "Should values for invalid fields be displayed (in messages with a 'valid fields' field)?")
	p_simplemsg_tcp.prefs["tcp_ports"             ] = Pref.range("TCP Ports", "11000,11002,50240,50241", "TCP ports the dissector should be registered for (default: 11000 (traj. relay), 11002 (state), 50240 (MotoROS traj. relay) and 50241 (MotorROS state)).", 65535)






	--
	-- protocol fields
	--
	local f = p_simplemsg_tcp.fields

	-- protocol fields: prefix and header
	f.pfx_hdr_len    = ProtoField.int32 ("simplemessage.pfx.length"    , "Packet Length"      , base.DEC, nil           , nil, "Total size of packet in bytes, excluding prefix")
	f.hdr_msg_type   = ProtoField.uint32("simplemessage.hdr.msg_type"  , "Message Type"       , base.HEX, pkt_types_str , nil, "Message type identifier")
	f.hdr_comm_type  = ProtoField.int32 ("simplemessage.hdr.comm_type" , "Communications Type", base.DEC, comm_types_str, nil, "Communications type idenfier (service, topic)")
	f.hdr_reply_type = ProtoField.int32 ("simplemessage.hdr.reply_code", "Reply Code"         , base.DEC, reply_code_str, nil, "Reply code (only for services)")

	-- protocol fields: JOINT_POSITION
	f.jp_seq_nr      = ProtoField.int32("simplemessage.jp.seq"       , "Sequence Number", base.DEC, nil, nil, "Index of point in trajectory")

	-- protocol fields: JOINT_TRAJ_PT
	f.jtpt_seq_nr    = ProtoField.int32("simplemessage.jtpt.seq"     , "Sequence Number", base.DEC, nil, nil, "Index of point in trajectory")
	f.jtpt_vel       = ProtoField.float("simplemessage.jtpt.velocity", "Velocity"       , "Velocity (controller specific) to be attained at this point")
	f.jtpt_dur       = ProtoField.float("simplemessage.jtpt.duration", "Duration"       , "Time (in seconds) allotted for motion to this point")

	-- protocol fields: STATUS
	f.rs_mode        = ProtoField.int32("simplemessage.rs.mode"            , "Mode           " , base.DEC, status_robotmode_str, nil, "Mode the controller is currently in")
	f.rs_estop       = ProtoField.int32("simplemessage.rs.e_stopped"       , "E-Stopped      " , base.DEC, status_tristate_str , nil, "Status of the e-stop on the controller")
	f.rs_drv_pwd     = ProtoField.int32("simplemessage.rs.drives_powered"  , "Drives Powered " , base.DEC, status_tristate_str , nil, "Status of servo power")
	f.rs_motpos      = ProtoField.int32("simplemessage.rs.motion_possible" , "Motion Possible" , base.DEC, status_tristate_str , nil, "Controller is ok to receive motion commands")
	f.rs_inmot       = ProtoField.int32("simplemessage.rs.in_motion"       , "In Motion      " , base.DEC, status_tristate_str , nil, "Robot is currently executing a command")
	f.rs_inerr       = ProtoField.int32("simplemessage.rs.in_error"        , "In Error       " , base.DEC, status_tristate_str , nil, "Controller in error mode")
	f.rs_errcode     = ProtoField.int32("simplemessage.rs.error_code"      , "Error Code     " , base.DEC, nil                 , nil, "If not zero: error code (controller specific)")

	-- protocol fields: JOINT_TRAJ_PT_FULL
	f.jtptf_robotid  = ProtoField.int32("simplemessage.jtptf.rid"     , "Robot ID"       , base.DEC, nil          , nil                          , "Robot identifier")
	f.jtptf_seq_nr   = ProtoField.int32("simplemessage.jtptf.seq"     , "Sequence Number", base.DEC, nil          , nil                          , "Index of point in trajectory")
	f.jtptf_vf       = ProtoField.uint8("simplemessage.jtptf.vf"      , "Valid Fields"   , base.HEX, nil          , nil                          , "Fields that contain valid data")
	f.jtptf_vf_time  = ProtoField.uint8("simplemessage.jtptf.vf.time" , "Time         "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_TIME        , "Validity of time field")
	f.jtptf_vf_pos   = ProtoField.uint8("simplemessage.jtptf.vf.pos"  , "Position     "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_POSITION    , "Validity of position data")
	f.jtptf_vf_vel   = ProtoField.uint8("simplemessage.jtptf.vf.vel"  , "Velocity     "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_VELOCITY    , "Validity of velocity data")
	f.jtptf_vf_accel = ProtoField.uint8("simplemessage.jtptf.vf.accel", "Acceleration "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_ACCELERATION, "Validity of acceleration data")
	f.jtptf_time     = ProtoField.float("simplemessage.jtptf.time"    , "Time"           , "Timestamp for data (seconds, optional)")

	-- protocol fields: JOINT_FEEDBACK
	f.jf_robotid  = ProtoField.int32("simplemessage.jf.rid"     , "Robot ID"       , base.DEC, nil         , nil                          , "Robot identifier")
	f.jf_vf       = ProtoField.uint8("simplemessage.jf.vf"      , "Valid Fields"   , base.HEX, nil         , nil                          , "Fields that contain valid data")
	f.jf_vf_time  = ProtoField.uint8("simplemessage.jf.vf.time" , "Time         "  , base.DEC, in_valid_str, VALID_FIELD_TYPE_TIME        , "Validity of time field")
	f.jf_vf_pos   = ProtoField.uint8("simplemessage.jf.vf.pos"  , "Position     "  , base.DEC, in_valid_str, VALID_FIELD_TYPE_POSITION    , "Validity of position data")
	f.jf_vf_vel   = ProtoField.uint8("simplemessage.jf.vf.vel"  , "Velocity     "  , base.DEC, in_valid_str, VALID_FIELD_TYPE_VELOCITY    , "Validity of velocity data")
	f.jf_vf_accel = ProtoField.uint8("simplemessage.jf.vf.accel", "Acceleration "  , base.DEC, in_valid_str, VALID_FIELD_TYPE_ACCELERATION, "Validity of acceleration data")
	f.jf_time     = ProtoField.float("simplemessage.jf.time"    , "Time"           , "Timestamp for data (seconds, optional)")

	-- protocol fields: MOTO_MOTION_CTRL
	f.mmc_robotid = ProtoField.int32("simplemessage.mmc.rid"     , "Robot ID"       , base.DEC, nil                 , nil, "Robot identifier")
	f.mmc_seq_nr  = ProtoField.int32("simplemessage.mmc.seq"     , "Sequence Number", base.DEC, nil                 , nil, "Message identifier")
	f.mmc_command = ProtoField.int32("simplemessage.mmc.command" , "Command"        , base.DEC, motoman_ctrl_cmd_str, nil, "Command to execute")

	-- protocol fields: MOTO_MOTION_REPLY
	f.mmr_robotid  = ProtoField.int32("simplemessage.mmr.rid"     , "Robot ID"       , base.DEC, nil                       , nil, "Robot identifier")
	f.mmr_seq_nr   = ProtoField.int32("simplemessage.mmr.seq"     , "Sequence Number", base.DEC, nil                       , nil, "Message identifier")
	f.mmr_command  = ProtoField.int32("simplemessage.mmr.command" , "Command"        , base.DEC, motoman_ctrl_cmd_str      , nil, "Command executed")
	f.mmr_res      = ProtoField.int32("simplemessage.mmr.result"  , "Result"         , base.DEC, motoman_reply_results_str , nil, "Result of executing specified command")
	f.mmr_subc     = ProtoField.int32("simplemessage.mmr.subcode" , "Subcode"        , base.DEC, motoman_reply_subcodes_str, nil, "More detailed result code")

	-- protocol fields: MOTOMAN_JOINT_TRAJ_PT_FULL_EX
	f.mmjtptfex_validgroups = ProtoField.int32("simplemessage.mmjtptfex.vg"      , "Valid Groups"   , base.DEC, nil          , nil                          , "Number of valid groups")
	f.mmjtptfex_seq_nr      = ProtoField.int32("simplemessage.mmjtptfex.seq"     , "Sequence Number", base.DEC, nil          , nil                          , "Index of point in trajectory")
	f.mmjtptfex_robotid     = ProtoField.int32("simplemessage.mmjtptfex.rid"     , "Robot ID"       , base.DEC, nil          , nil                          , "Robot identifier")
	f.mmjtptfex_vf          = ProtoField.uint8("simplemessage.mmjtptfex.vf"      , "Valid Fields"   , base.HEX, nil          , nil                          , "Fields that contain valid data")
	f.mmjtptfex_vf_time     = ProtoField.uint8("simplemessage.mmjtptfex.vf.time" , "Time         "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_TIME        , "Validity of time field")
	f.mmjtptfex_vf_pos      = ProtoField.uint8("simplemessage.mmjtptfex.vf.pos"  , "Position     "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_POSITION    , "Validity of position data")
	f.mmjtptfex_vf_vel      = ProtoField.uint8("simplemessage.mmjtptfex.vf.vel"  , "Velocity     "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_VELOCITY    , "Validity of velocity data")
	f.mmjtptfex_vf_accel    = ProtoField.uint8("simplemessage.mmjtptfex.vf.accel", "Acceleration "  , base.DEC, in_valid_str , VALID_FIELD_TYPE_ACCELERATION, "Validity of acceleration data")
	f.mmjtptfex_time        = ProtoField.float("simplemessage.mmjtptfex.time"    , "Time"           , "Timestamp for data (seconds, optional)")

	-- protocol fields: MOTOMAN_JOINT_FEEDBACK_EX
	f.mmjfex_numgroups = ProtoField.int32("simplemessage.mmjfex.numgroups", "Number of Groups", base.DEC, nil         , nil                          , "Number of groups")
	f.mmjfex_robotid   = ProtoField.int32("simplemessage.mmjfex.rid"      , "Robot ID"        , base.DEC, nil         , nil                          , "Robot identifier")
	f.mmjfex_vf        = ProtoField.uint8("simplemessage.mmjfex.vf"       , "Valid Fields"    , base.HEX, nil         , nil                          , "Fields that contain valid data")
	f.mmjfex_vf_time   = ProtoField.uint8("simplemessage.mmjfex.vf.time"  , "Time         "   , base.DEC, in_valid_str, VALID_FIELD_TYPE_TIME        , "Validity of time field")
	f.mmjfex_vf_pos    = ProtoField.uint8("simplemessage.mmjfex.vf.pos"   , "Position     "   , base.DEC, in_valid_str, VALID_FIELD_TYPE_POSITION    , "Validity of position data")
	f.mmjfex_vf_vel    = ProtoField.uint8("simplemessage.mmjfex.vf.vel"   , "Velocity     "   , base.DEC, in_valid_str, VALID_FIELD_TYPE_VELOCITY    , "Validity of velocity data")
	f.mmjfex_vf_accel  = ProtoField.uint8("simplemessage.mmjfex.vf.accel" , "Acceleration "   , base.DEC, in_valid_str, VALID_FIELD_TYPE_ACCELERATION, "Validity of acceleration data")
	f.mmjfex_time      = ProtoField.float("simplemessage.mmjfex.time"     , "Time"            , "Timestamp for data (seconds, optional)")






	--
	-- Helper functions
	--

	local function pref_uint(buf, offset, len)
		if config.target_be then
			return buf(offset, len):uint()
		end
		return buf(offset, len):le_uint()
	end

	local function pref_int(buf, offset, len)
		if config.target_be then
			return buf(offset, len):int()
		end
		return buf(offset, len):le_int()
	end

	local function pref_uint64(buf, offset, len)
		if config.target_be then
			return buf(offset, len):uint64()
		end
		return buf(offset, len):le_uint64()
	end

	local function pref_int64(buf, offset, len)
		if config.target_be then
			return buf(offset, len):int64()
		end
		return buf(offset, len):le_int64()
	end

	local function pref_float(buf, offset, len)
		if config.target_be then
			return buf(offset, len):float()
		end
		return buf(offset, len):le_float()
	end

	local function pref_tree_add(tree, field, buf, offset, len)
		if config.target_be then
			return tree:add(field, buf(offset, len))
		else
			return tree:add_le(field, buf(offset, len))
		end
	end

	local function add_floatf_fmt(buf, tree, offset, len, text, format)
		if ((len % 4) ~= 0) or (len > 8) then return nil end

		return tree:add(buf(offset, len), text)
			:append_text(_F(": %s",
				_F(format,
				   pref_float(buf, offset, len)),
				   pref_uint(buf, offset, len)))
	end

	local function add_floatf(buf, tree, offset, len, text)
		return add_floatf_fmt(buf, tree, offset, len, text, "%14.9f")
	end

	local function str_or_none(arr, arg)
		return arr[arg] or "Unknown"
	end

	local function stringify_flagbits(bit_val, bit_tab)
		local temp = {}
		for k, v in pairs(bit_tab) do
			if (bit.band(bit_val, k) > 0) then table.insert(temp, v) end
		end
		return table.concat(temp, ", ")
	end






	--
	-- Dissection subfunctions
	--


	--
	-- Header
	--
	local function disf_header(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		--
		local hdr_tree = lt:add(buf(offset_, 0), "Header")

		-- message type
		pref_tree_add(hdr_tree, f.hdr_msg_type, buf, offset_, 4)
		offset_ = offset_ + 4

		-- comm type
		pref_tree_add(hdr_tree, f.hdr_comm_type, buf, offset_, 4)
		offset_ = offset_ + 4

		-- reply type
		pref_tree_add(hdr_tree, f.hdr_reply_type, buf, offset_, 4)
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		hdr_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- array of N floats
	--
	local function disf_float_array(buf, pkt, tree, offset, array_sz, text, item_fmt)
		--
		local offset_ = offset
		local lt = tree

		--
		local jd_tree = lt:add(buf(offset_, 0), text)

		for i = 0, (array_sz - 1) do
			add_floatf(buf, jd_tree, offset_, 4, _F(item_fmt, i))
			offset_ = offset_ + 4
		end

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		jd_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- PING
	--
	local function disf_ping(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- joint data
		offset_ = offset_ + disf_float_array(buf, pkt, tree, offset_, 10,
			"Data", "J%d")


		-- nr of bytes we consumed
		return (offset_ - offset)
	end



	--
	-- JOINT_POSITION
	--
	local function disf_joint_position(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- sequence number
		local seq_nr = pref_int(buf, offset_, 4)
		local seq_field = pref_tree_add(body_tree, f.jp_seq_nr, buf, offset_, 4)
		offset_ = offset_ + 4
		if (seq_nr < 0) then
			seq_field:set_text(_F("Sequence Number: %s (%d)", str_or_none(special_seq_nr_str, seq_nr), seq_nr))
		end

		-- joint data
		offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
			"Joint Data", "J%d")

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- JOINT_TRAJ_PT
	--
	local function disf_joint_traj_point(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- sequence number
		local seq_nr = pref_int(buf, offset_, 4)
		local seq_field = pref_tree_add(body_tree, f.jtpt_seq_nr, buf, offset_, 4)
		offset_ = offset_ + 4
		if (seq_nr < 0) then
			seq_field:set_text(_F("Sequence Number: %s (%d)", str_or_none(special_seq_nr_str, seq_nr), seq_nr))
		end

		-- joint data
		offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
			"Joint Data", "J%d")

		-- velocity
		pref_tree_add(body_tree, f.jtpt_vel, buf, offset_, 4)
		offset_ = offset_ + 4

		-- duration
		pref_tree_add(body_tree, f.jtpt_dur, buf, offset_, 4)
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- STATUS
	--
	local function disf_status(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- drives powered
		pref_tree_add(body_tree, f.rs_drv_pwd, buf, offset_, 4)
		offset_ = offset_ + 4

		-- e-stopped
		pref_tree_add(body_tree, f.rs_estop, buf, offset_, 4)
		offset_ = offset_ + 4

		-- error code
		pref_tree_add(body_tree, f.rs_errcode, buf, offset_, 4)
		offset_ = offset_ + 4

		-- in error
		pref_tree_add(body_tree, f.rs_inerr, buf, offset_, 4)
		offset_ = offset_ + 4

		-- in motion
		pref_tree_add(body_tree, f.rs_inmot, buf, offset_, 4)
		offset_ = offset_ + 4

		-- mode
		pref_tree_add(body_tree, f.rs_mode, buf, offset_, 4)
		offset_ = offset_ + 4

		-- motion possible
		pref_tree_add(body_tree, f.rs_motpos, buf, offset_, 4)
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- JOINT_TRAJ_PT_FULL
	--
	local function disf_joint_traj_point_full(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- robot id
		pref_tree_add(body_tree, f.jtptf_robotid, buf, offset_, 4)
		offset_ = offset_ + 4

		-- sequence number
		local seq_nr = pref_int(buf, offset_, 4)
		local seq_field = pref_tree_add(body_tree, f.jtptf_seq_nr, buf, offset_, 4)
		offset_ = offset_ + 4
		if (seq_nr < 0) then
			seq_field:set_text(_F("Sequence Number: %s (%d)", str_or_none(special_seq_nr_str, seq_nr), seq_nr))
		end

		-- valid_fields
		local valid_fields = pref_uint(buf, offset_, 4)
		local vf_lo = pref_tree_add(body_tree, f.jtptf_vf, buf, offset_, 4)
		-- bitfield
		pref_tree_add(vf_lo, f.jtptf_vf_time,  buf, offset_, 4)
		pref_tree_add(vf_lo, f.jtptf_vf_pos,   buf, offset_, 4)
		pref_tree_add(vf_lo, f.jtptf_vf_vel,   buf, offset_, 4)
		pref_tree_add(vf_lo, f.jtptf_vf_accel, buf, offset_, 4)
		offset_ = offset_ + 4

		-- append high bit flags to bitfield parent item
		vf_lo:append_text(_F(" (%s)", stringify_flagbits(valid_fields, valid_field_type_str)))

		-- time
		if (bit.band(VALID_FIELD_TYPE_TIME, valid_fields) > 0) or (config.display_invalid_fields) then
			pref_tree_add(body_tree, f.jtptf_time, buf, offset_, 4)
		end
		offset_ = offset_ + 4

		-- positions
		if (bit.band(VALID_FIELD_TYPE_POSITION, valid_fields) > 0) or (config.display_invalid_fields) then
			offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
				"Positions", "J%d")
		else
			-- TODO: remove hard-coded float and array size
			offset_ = offset_ + (10 * 4)
		end

		-- velocities
		if (bit.band(VALID_FIELD_TYPE_VELOCITY, valid_fields) > 0) or (config.display_invalid_fields) then
			offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
				"Velocities", "J%d")
		else
			-- TODO: remove hard-coded float and array size
			offset_ = offset_ + (10 * 4)
		end

		-- accelerations
		if (bit.band(VALID_FIELD_TYPE_ACCELERATION, valid_fields) > 0) or (config.display_invalid_fields) then
			offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
				"Accelerations", "J%d")
		else
			-- TODO: remove hard-coded float and array size
			offset_ = offset_ + (10 * 4)
		end

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- JOINT_FEEDBACK
	--
	local function disf_joint_feedback(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- robot id
		pref_tree_add(body_tree, f.jf_robotid, buf, offset_, 4)
		offset_ = offset_ + 4

		-- valid_fields
		local valid_fields = pref_uint(buf, offset_, 4)
		local vf_lo = pref_tree_add(body_tree, f.jf_vf, buf, offset_, 4)
		-- bitfield
		pref_tree_add(vf_lo, f.jf_vf_time,  buf, offset_, 4)
		pref_tree_add(vf_lo, f.jf_vf_pos,   buf, offset_, 4)
		pref_tree_add(vf_lo, f.jf_vf_vel,   buf, offset_, 4)
		pref_tree_add(vf_lo, f.jf_vf_accel, buf, offset_, 4)
		offset_ = offset_ + 4

		-- append high bit flags to bitfield parent item
		vf_lo:append_text(_F(" (%s)", stringify_flagbits(valid_fields, valid_field_type_str)))

		-- time
		if (bit.band(VALID_FIELD_TYPE_TIME, valid_fields) > 0) or (config.display_invalid_fields) then
			pref_tree_add(body_tree, f.jf_time, buf, offset_, 4)
		end
		offset_ = offset_ + 4

		-- positions
		if (bit.band(VALID_FIELD_TYPE_POSITION, valid_fields) > 0) or (config.display_invalid_fields) then
			offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
				"Positions", "J%d")
		else
			-- TODO: remove hard-coded float and array size
			offset_ = offset_ + (10 * 4)
		end

		-- velocities
		if (bit.band(VALID_FIELD_TYPE_VELOCITY, valid_fields) > 0) or (config.display_invalid_fields) then
			offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
				"Velocities", "J%d")
		else
			-- TODO: remove hard-coded float and array size
			offset_ = offset_ + (10 * 4)
		end

		-- accelerations
		if (bit.band(VALID_FIELD_TYPE_ACCELERATION, valid_fields) > 0) or (config.display_invalid_fields) then
			offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
				"Accelerations", "J%d")
		else
			-- TODO: remove hard-coded float and array size
			offset_ = offset_ + (10 * 4)
		end

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- MOTO_MOTION_CTRL
	--
	local function disf_motoman_ctrl(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- robot id
		pref_tree_add(body_tree, f.mmc_robotid, buf, offset_, 4)
		offset_ = offset_ + 4

		-- sequence number
		pref_tree_add(body_tree, f.mmc_seq_nr, buf, offset_, 4)
		offset_ = offset_ + 4

		-- command
		pref_tree_add(body_tree, f.mmc_command, buf, offset_, 4)
		offset_ = offset_ + 4

		--
		offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
			"Data (reserved)", "J%d")

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- MOTO_MOTION_REPLY
	--
	local function disf_motoman_reply(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- robot id
		pref_tree_add(body_tree, f.mmr_robotid, buf, offset_, 4)
		offset_ = offset_ + 4

		-- sequence number
		pref_tree_add(body_tree, f.mmr_seq_nr, buf, offset_, 4)
		offset_ = offset_ + 4

		-- command
		pref_tree_add(body_tree, f.mmr_command, buf, offset_, 4)
		offset_ = offset_ + 4

		-- result
		pref_tree_add(body_tree, f.mmr_res, buf, offset_, 4)
		offset_ = offset_ + 4

		-- subcode
		pref_tree_add(body_tree, f.mmr_subc, buf, offset_, 4)
		offset_ = offset_ + 4

		--
		offset_ = offset_ + disf_float_array(buf, pkt, body_tree, offset_, 10,
			"Data (reserved)", "J%d")

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- MOTO_JOINT_TRAJ_PT_FULL_EX
	--
	local function disf_moto_joint_traj_point_full_ex(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- number of valid groups
		local valid_groups = pref_uint(buf, offset_, 4)
		pref_tree_add(body_tree, f.mmjtptfex_validgroups, buf, offset_, 4)
		offset_ = offset_ + 4

		-- sequence number
		pref_tree_add(body_tree, f.mmjtptfex_seq_nr, buf, offset_, 4)
		offset_ = offset_ + 4

		for i = 0, (valid_groups - 1) do
			--
			local group_tree_start = offset_
			local group_tree = body_tree:add(buf(offset_, 0), _F("Group %d", i))

			-- robot id
			pref_tree_add(group_tree, f.mmjtptfex_robotid, buf, offset_, 4)
			offset_ = offset_ + 4

			-- valid_fields
			local valid_fields = pref_uint(buf, offset_, 4)
			local vf_lo = pref_tree_add(group_tree, f.mmjtptfex_vf, buf, offset_, 4)

			-- bitfield
			pref_tree_add(vf_lo, f.mmjtptfex_vf_time,  buf, offset_, 4)
			pref_tree_add(vf_lo, f.mmjtptfex_vf_pos,   buf, offset_, 4)
			pref_tree_add(vf_lo, f.mmjtptfex_vf_vel,   buf, offset_, 4)
			pref_tree_add(vf_lo, f.mmjtptfex_vf_accel, buf, offset_, 4)
			offset_ = offset_ + 4

			-- append high bit flags to bitfield parent item
			vf_lo:append_text(_F(" (%s)", stringify_flagbits(valid_fields, valid_field_type_str)))

			-- time
			if (bit.band(VALID_FIELD_TYPE_TIME, valid_fields) > 0) or (config.display_invalid_fields) then
				pref_tree_add(group_tree, f.mmjtptfex_time, buf, offset_, 4)
			end
			offset_ = offset_ + 4

			-- positions
			if (bit.band(VALID_FIELD_TYPE_POSITION, valid_fields) > 0) or (config.display_invalid_fields) then
				offset_ = offset_ + disf_float_array(buf, pkt, group_tree, offset_, 10,
					"Positions", "J%d")
			else
				-- TODO: remove hard-coded float and array size
				offset_ = offset_ + (10 * 4)
			end

			-- velocities
			if (bit.band(VALID_FIELD_TYPE_VELOCITY, valid_fields) > 0) or (config.display_invalid_fields) then
				offset_ = offset_ + disf_float_array(buf, pkt, group_tree, offset_, 10,
					"Velocities", "J%d")
			else
				-- TODO: remove hard-coded float and array size
				offset_ = offset_ + (10 * 4)
			end

			-- accelerations
			if (bit.band(VALID_FIELD_TYPE_ACCELERATION, valid_fields) > 0) or (config.display_invalid_fields) then
				offset_ = offset_ + disf_float_array(buf, pkt, group_tree, offset_, 10,
					"Accelerations", "J%d")
			else
				-- TODO: remove hard-coded float and array size
				offset_ = offset_ + (10 * 4)
			end

			-- correct length of TreeItem
			group_tree:set_len(offset_ - group_tree_start)
		end

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- MOTO_JOINT_FEEDBACK_EX
	--
	local function disf_moto_joint_feedback_ex(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- body
		local body_tree = lt:add(buf(offset_, 0), "Body")

		-- number of groups
		pref_tree_add(body_tree, f.mmjfex_numgroups, buf, offset_, 4)
		local num_groups = pref_uint(buf, offset_, 4)
		offset_ = offset_ + 4

		for i = 0, (num_groups - 1) do
			--
			local group_tree_start = offset_
			local group_tree = body_tree:add(buf(offset_, 0), _F("Group %d", i))

			-- group ID
			pref_tree_add(group_tree, f.mmjfex_robotid, buf, offset_, 4)
			offset_ = offset_ + 4

			-- valid_fields
			local valid_fields = pref_uint(buf, offset_, 4)
			local vf_lo = pref_tree_add(group_tree, f.mmjfex_vf, buf, offset_, 4)

			-- bitfield
			pref_tree_add(vf_lo, f.mmjfex_vf_time,  buf, offset_, 4)
			pref_tree_add(vf_lo, f.mmjfex_vf_pos,   buf, offset_, 4)
			pref_tree_add(vf_lo, f.mmjfex_vf_vel,   buf, offset_, 4)
			pref_tree_add(vf_lo, f.mmjfex_vf_accel, buf, offset_, 4)
			offset_ = offset_ + 4

			-- append high bit flags to bitfield parent item
			vf_lo:append_text(_F(" (%s)", stringify_flagbits(valid_fields, valid_field_type_str)))

			-- time
			if (bit.band(VALID_FIELD_TYPE_TIME, valid_fields) > 0) or (config.display_invalid_fields) then
				pref_tree_add(group_tree, f.mmjfex_time, buf, offset_, 4)
			end
			offset_ = offset_ + 4

			-- positions
			if (bit.band(VALID_FIELD_TYPE_POSITION, valid_fields) > 0) or (config.display_invalid_fields) then
				offset_ = offset_ + disf_float_array(buf, pkt, group_tree, offset_, 10,
					"Positions", "J%d")
			else
				-- TODO: remove hard-coded float and array size
				offset_ = offset_ + (10 * 4)
			end

			-- velocities
			if (bit.band(VALID_FIELD_TYPE_VELOCITY, valid_fields) > 0) or (config.display_invalid_fields) then
				offset_ = offset_ + disf_float_array(buf, pkt, group_tree, offset_, 10,
					"Velocities", "J%d")
			else
				-- TODO: remove hard-coded float and array size
				offset_ = offset_ + (10 * 4)
			end

			-- accelerations
			if (bit.band(VALID_FIELD_TYPE_ACCELERATION, valid_fields) > 0) or (config.display_invalid_fields) then
				offset_ = offset_ + disf_float_array(buf, pkt, group_tree, offset_, 10,
					"Accelerations", "J%d")
			else
				-- TODO: remove hard-coded float and array size
				offset_ = offset_ + (10 * 4)
			end

			-- correct length of TreeItem
			group_tree:set_len(offset_ - group_tree_start)
		end

		-- nr of bytes we consumed
		local tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end



	--
	-- Default parser
	--
	local function disf_default(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, lt, offset_)

		--
		local zlen = buf:len() - offset_
		local z = lt:add(buf(offset_, zlen), _F("Unhandled, %u bytes", zlen))
		offset_ = offset_ + zlen

		-- nr of bytes we consumed
		return (offset_ - offset)
	end






	--
	-- message type -> dissection function map
	--
	local map_msg_type_to_disf = {
		[MSG_PING                      ] = disf_ping,
		[MSG_JOINT_POSITION            ] = disf_joint_position,
		[MSG_JOINT_TRAJ_PT             ] = disf_joint_traj_point,
		[MSG_STATUS                    ] = disf_status,
		[MSG_JOINT_TRAJ_PT_FULL        ] = disf_joint_traj_point_full,
		[MSG_JOINT_FEEDBACK            ] = disf_joint_feedback,

		[MSG_MOTO_MOTION_CTRL          ] = disf_motoman_ctrl,
		[MSG_MOTO_MOTION_REPLY         ] = disf_motoman_reply,
		[MSG_MOTO_JOINT_TRAJ_PT_FULL_EX] = disf_moto_joint_traj_point_full_ex,
		[MSG_MOTO_JOINT_FEEDBACK_EX    ] = disf_moto_joint_feedback_ex,
		-- facilitate dissection of legacy captures (before renumbering of
		-- Motoman msgs)
		-- TODO: this will need to be removed once IDs 0x10 and 0x11 are
		--       assigned to other msgs
		[0x10                          ] = disf_moto_joint_traj_point_full_ex,
		[0x11                          ] = disf_moto_joint_feedback_ex,
	}






	--
	-- main parser function
	--
	local function parse(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		-- add 'prefix' tree
		local plen = 1 * 4
		local pfx_tree = lt:add(buf(offset_, plen), "Prefix")

		-- extract packet length
		pref_tree_add(pfx_tree, f.pfx_hdr_len, buf, offset_, 4)
		offset_ = offset_ + 4

		-- extract message type
		local msg_type = pref_uint(buf, offset_, 4)

		-- get dissection function based on msg type
		local f = map_msg_type_to_disf[msg_type] or disf_default

		-- dissect using the function
		offset_ = offset_ + f(buf, pkt, lt, offset_)

		-- nr of bytes we consumed
		return (offset_ - offset)
	end






	--
	-- actual dissector method
	--
	function p_simplemsg_tcp.dissector(buf, pkt, tree)
		-- check pkt len
		local buf_len = buf:len()
		if (buf_len <= 0) then return end

		-- either we resume dissecting, or we start fresh
		local offset = pkt.desegment_offset or 0

		-- keep dissecting as long as there are bytes available
		while true do
			-- TODO: this probably isn't too good an idea if there are streams
			--       of more than one robot in the capture (with different
			--       endianness)
			-- detect endianness if enabled
			local pkt_len = pref_uint(buf, offset, 4)
			if (config.autodetect_endianness) then
				-- make an effort
				if (pkt_len > 0xFFFF) then
					-- swap config
					config.target_be = not config.target_be
					-- TODO: also update pref
				end
			end

			-- re-read (in case config item was updated)
			pkt_len = pref_uint(buf, offset, 4)

			-- TODO: add some sanity check on packet length?

			-- add prefix length to it
			pkt_len = pkt_len + 4

			-- make sure we have enough for coming packet. If not, signal
			-- caller by setting appropriate fields in 'pkt' argument
			local nextpkt = offset + pkt_len
			if (nextpkt > buf_len) then
				pkt.desegment_len = nextpkt - buf_len
				pkt.desegment_offset = offset
				return
			end

			-- have enough data: add protocol to tree
			local subtree = tree:add(p_simplemsg_tcp, buf(offset, pkt_len))

			-- create string repr of packet type
			local pkt_type  = pref_uint(buf, (offset + 4), 4)
			local pkt_t_str = str_or_none(pkt_types_str, pkt_type)

			-- add some extra info to the protocol line in the packet treeview
			local s_endiannes = "little"
			if (config.target_be) then s_endiannes = "big" end
			subtree:append_text(_F(", %s (0x%02x), %u bytes, %s-endian",
				pkt_t_str, pkt_type, pkt_len, s_endiannes))

			-- add info to top pkt view
			pkt.cols.protocol = p_simplemsg_tcp.name

			-- use offset in buffer to determine if we need to append to or set
			-- the info column
			if (offset > 0) then
				pkt.cols.info:append(_F(", %s (0x%02x)", pkt_t_str, pkt_type))
			else
				pkt.cols.info = _F("%s (0x%02x)", pkt_t_str, pkt_type)
			end

			-- dissect rest of pkt
			local res = parse(buf, pkt, subtree, offset)

			-- increment 'read pointer' and stop if we've dissected all bytes
			-- in the buffer
			offset = nextpkt
			if (offset == buf_len) then return end

		-- end-of-dissect-while
		end

	-- end-of-dissector
	end






	--
	-- init routine
	--
	function p_simplemsg_tcp.init()
		-- update config from prefs
		config.target_be              = p_simplemsg_tcp.prefs["target_be"]
		config.autodetect_endianness  = p_simplemsg_tcp.prefs["autodetect_endianness"]
		config.display_invalid_fields = p_simplemsg_tcp.prefs["display_invalid_fields"]

		-- register dissector on configured ports
		local tcp_dissector_table = DissectorTable.get("tcp.port")
		tcp_dissector_table:add(p_simplemsg_tcp.prefs.tcp_ports, p_simplemsg_tcp)
	end

end
