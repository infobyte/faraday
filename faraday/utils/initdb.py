# Related third party imports
from sqlalchemy.exc import IntegrityError

# Local application imports
from faraday.server.models import PermissionsUnitAction
from faraday.server.utils.permissions import (
    GROUP_ADMIN,
    GROUP_AGENTS,
    GROUP_ALL,
    GROUP_ANALYTICS,
    GROUP_ASSETS,
    GROUP_COMMENTS,
    GROUP_CREDENTIALS,
    GROUP_EXECUTIVE_REPORTS,
    GROUP_INTEGRATIONS,
    GROUP_PIPELINES,
    GROUP_PLANNERS,
    GROUP_VULNERABILITIES,
    UNIT_2FA,
    UNIT_ACTIVE_INTEGRATIONS,
    UNIT_ADMIN,
    UNIT_AGENTS,
    UNIT_AGENTS_SCHEDULE,
    UNIT_AGENTS_TOKENS,
    UNIT_ANALYTICS,
    UNIT_BASE,
    UNIT_CLOUD_AGENTS,
    UNIT_CLOUD_AGENTS_SCHEDULE,
    UNIT_COMMANDS,
    UNIT_COMMENTS,
    UNIT_CONFIG,
    UNIT_CREDENTIALS,
    UNIT_CUSTOM_FIELDS,
    UNIT_EXECUTIVE_REPORTS,
    UNIT_EXPLOITS,
    UNIT_FORGOT_PASSWORD,
    UNIT_GITLAB,
    UNIT_HOSTS,
    UNIT_INFO,
    UNIT_INTEGRATIONS_AUTH,
    UNIT_JIRA,
    UNIT_JOBS,
    UNIT_LOGS,
    UNIT_NOTIFICATIONS,
    UNIT_PIPELINES,
    UNIT_PLANNERS,
    UNIT_PREFERENCES,
    UNIT_ROLES,
    UNIT_SEARCH_FILTERS,
    UNIT_SERVICE_DESK,
    UNIT_SERVICE_NOW,
    UNIT_SERVICES,
    UNIT_SESSIONS,
    UNIT_SETTINGS,
    UNIT_SWAGGER,
    UNIT_TAGS,
    UNIT_TASKS,
    UNIT_TOKENS,
    UNIT_UNIQUE_COMMENT,
    UNIT_USER_TOKENS,
    UNIT_USERS,
    UNIT_VULNERABILITIES,
    UNIT_VULNERABILITY_TEMPLATES,
    UNIT_WEB_HELP_DESK,
    UNIT_WEBSOCKETS,
    UNIT_WHOAMI,
    UNIT_WORKSPACES,
)

CREATE = PermissionsUnitAction.CREATE_ACTION
READ = PermissionsUnitAction.READ_ACTION
UPDATE = PermissionsUnitAction.UPDATE_ACTION
DELETE = PermissionsUnitAction.DELETE_ACTION
RUN = PermissionsUnitAction.RUN_ACTION
TAG = PermissionsUnitAction.TAG_ACTION


def initdb_roles_and_permissions(db_engine):
    try:
        # Insert rows into the 'faraday_role' table
        db_engine.execute(
            "INSERT INTO faraday_role(name, weight, custom, description) VALUES "
            "('admin', 10, false, 'Full control over Faraday including user management, workspaces, vulnerabilities, reports, automation and system settings.'), "
            "('asset_owner', 20, false, 'Can access assigned workspaces, review vulnerabilities, update their status, and add comments & tags.'), "
            "('pentester', 30, false, 'Can access assigned workspaces, create/edit vulnerabilities, execute agents, and generate executive reports.'), "
            "('client', 40, false, 'Read-only access to permitted workspaces; cannot make any modifications.');"
        )

        # Insert rows into the 'permissions_group' table
        db_engine.execute(
            f"INSERT INTO permissions_group (id, name) VALUES (1, '{GROUP_ADMIN}'), (2, '{GROUP_ALL}'), (3, '{GROUP_INTEGRATIONS}'), (4, '{GROUP_AGENTS}'), (5, '{GROUP_ANALYTICS}'), "  # nosec B608
            f"(6, '{GROUP_VULNERABILITIES}'), (7, '{GROUP_COMMENTS}'), (8, '{GROUP_ASSETS}'), (9, '{GROUP_PLANNERS}'), (10, '{GROUP_EXECUTIVE_REPORTS}'), "  # nosec B608
            f"(13, '{GROUP_PIPELINES}'), (15, '{GROUP_CREDENTIALS}');"  # nosec B608
        )

        # Insert rows into the 'permissions_unit' table
        db_engine.execute(  # nosec
            f"INSERT INTO permissions_unit (id, name, permissions_group_id) VALUES (1, '{UNIT_USERS}', 1), (2, '{UNIT_LOGS}', 1), "  # nosec B608
            f"(3, '{UNIT_TOKENS}', 2), (4, '{UNIT_WHOAMI}', 2), (5, '{UNIT_SWAGGER}', 2), (6, '{UNIT_EXPLOITS}', 2), (7, '{UNIT_NOTIFICATIONS}', 2), (8, '{UNIT_INFO}', 2), "  # nosec B608
            f"(9, '{UNIT_PREFERENCES}', 2), (10, '{UNIT_SEARCH_FILTERS}', 2), (11, '{UNIT_TAGS}', 2), (12, '{UNIT_SESSIONS}', 2), (13, '{UNIT_COMMANDS}', 2), (42, '{UNIT_2FA}', 2), (43, '{UNIT_FORGOT_PASSWORD}', 2), "  # nosec B608
            f"(14, '{UNIT_GITLAB}', 3), (15, '{UNIT_JIRA}', 3), (16, '{UNIT_SERVICE_DESK}', 3), (17, '{UNIT_SERVICE_NOW}', 3), (18, '{UNIT_WEB_HELP_DESK}', 3), (19, '{UNIT_ACTIVE_INTEGRATIONS}', 3), "  # nosec B608
            f"(20, '{UNIT_AGENTS}', 4), (21, '{UNIT_AGENTS_SCHEDULE}', 4), (22, '{UNIT_CLOUD_AGENTS}', 4), (23, '{UNIT_CLOUD_AGENTS_SCHEDULE}', 4), (24, '{UNIT_AGENTS_TOKENS}', 4), "  # nosec B608
            f"(25, '{UNIT_ANALYTICS}', 5), (26, '{UNIT_VULNERABILITIES}', 6), (28, '{UNIT_CUSTOM_FIELDS}', 6), (29, '{UNIT_VULNERABILITY_TEMPLATES}', 6), "  # nosec B608
            f"(30, '{UNIT_COMMENTS}', 7), (31, '{UNIT_UNIQUE_COMMENT}', 7), (32, '{UNIT_HOSTS}', 8), (33, '{UNIT_SERVICES}', 8), (34, '{UNIT_PLANNERS}', 9), (35, '{UNIT_EXECUTIVE_REPORTS}', 10), "  # nosec B608
            f"(36, '{UNIT_SETTINGS}', 1), (37, '{UNIT_USER_TOKENS}', 2), (38, '{UNIT_PIPELINES}', 13), (39, '{UNIT_JOBS}', 13), (40, '{UNIT_WORKSPACES}', 1), (41, '{UNIT_INTEGRATIONS_AUTH}', 3), "  # nosec B608
            f"(44, '{UNIT_CREDENTIALS}', 15), (45, '{UNIT_CONFIG}', 2), (46, '{UNIT_WEBSOCKETS}', 2), (48, '{UNIT_BASE}', 1), (49, '{UNIT_ADMIN}', 1), (50, '{UNIT_ROLES}', 1), (51, '{UNIT_TASKS}', 9);"  # nosec B608
        )

        # Insert rows into the 'permissions_unit_action' table
        db_engine.execute(  # nosec
            f"INSERT INTO permissions_unit_action (id, action_type, permissions_unit_id) VALUES "
            f"(1, '{CREATE}', 1), (2, '{READ}', 1), (3, '{UPDATE}', 1), (4, '{DELETE}', 1), "  # nosec B608
            f"(5, '{READ}', 2), (6, '{READ}', 3), (7, '{READ}', 4), (8, '{READ}', 5), (9, '{READ}', 6), "  # nosec B608
            f"(10, '{CREATE}', 7), (11, '{READ}', 7), (12, '{UPDATE}', 7), (13, '{DELETE}', 7), "  # nosec B608
            f"(14, '{READ}', 8), (15, '{READ}', 9), (16, '{READ}', 10), (17, '{READ}', 12), "  # nosec B608
            f"(18, '{CREATE}', 11), (19, '{READ}', 11), (20, '{UPDATE}', 11), (21, '{DELETE}', 11), "  # nosec B608
            f"(22, '{CREATE}', 13), (23, '{READ}', 13), (24, '{UPDATE}', 13), (25, '{DELETE}', 13), "  # nosec B608
            f"(26, '{CREATE}', 14), (27, '{READ}', 14), (28, '{UPDATE}', 14), (29, '{DELETE}', 14), "  # nosec B608
            f"(30, '{CREATE}', 15), (31, '{READ}', 15), (32, '{UPDATE}', 15), (33, '{DELETE}', 15), "  # nosec B608
            f"(34, '{CREATE}', 16), (35, '{READ}', 16), (36, '{UPDATE}', 16), (37, '{DELETE}', 16), "  # nosec B608
            f"(38, '{CREATE}', 17), (39, '{READ}', 17), (40, '{UPDATE}', 17), (41, '{DELETE}', 17), "  # nosec B608
            f"(42, '{CREATE}', 18), (43, '{READ}', 18), (44, '{UPDATE}', 18), (45, '{DELETE}', 18), "  # nosec B608
            f"(46, '{READ}', 19), (47, '{READ}', 24), (49, '{CREATE}', 31), "  # nosec B608
            f"(50, '{CREATE}', 20), (51, '{READ}', 20), (52, '{UPDATE}', 20), (53, '{DELETE}', 20), "  # nosec B608
            f"(54, '{CREATE}', 21), (55, '{READ}', 21), (56, '{UPDATE}', 21), (57, '{DELETE}', 21), "  # nosec B608
            f"(58, '{CREATE}', 22), (59, '{READ}', 22), (60, '{UPDATE}', 22), (61, '{DELETE}', 22), "  # nosec B608
            f"(62, '{CREATE}', 23), (63, '{READ}', 23), (64, '{UPDATE}', 23), (65, '{DELETE}', 23), "  # nosec B608
            f"(66, '{CREATE}', 25), (67, '{READ}', 25), (68, '{UPDATE}', 25), (69, '{DELETE}', 25), "  # nosec B608
            f"(70, '{CREATE}', 26), (71, '{READ}', 26), (72, '{UPDATE}', 26), (73, '{DELETE}', 26), "  # nosec B608
            f"(74, '{CREATE}', 28), (75, '{READ}', 28), (76, '{UPDATE}', 28), (77, '{DELETE}', 28), "  # nosec B608
            f"(78, '{CREATE}', 29), (79, '{READ}', 29), (80, '{UPDATE}', 29), (81, '{DELETE}', 29), "  # nosec B608
            f"(82, '{CREATE}', 30), (83, '{READ}', 30), (84, '{UPDATE}', 30), (85, '{DELETE}', 30), "  # nosec B608
            f"(86, '{CREATE}', 32), (87, '{READ}', 32), (88, '{UPDATE}', 32), (89, '{DELETE}', 32), "  # nosec B608
            f"(90, '{CREATE}', 33), (91, '{READ}', 33), (92, '{UPDATE}', 33), (93, '{DELETE}', 33), "  # nosec B608
            f"(94, '{CREATE}', 34), (95, '{READ}', 34), (96, '{UPDATE}', 34), (97, '{DELETE}', 34), "  # nosec B608
            f"(98, '{CREATE}', 35), (99, '{READ}', 35), (100, '{UPDATE}', 35), (101, '{DELETE}', 35), "  # nosec B608
            f"(102, '{CREATE}', 36), (103, '{READ}', 36), (104, '{UPDATE}', 36), (105, '{DELETE}', 36), "  # nosec B608
            f"(106, '{CREATE}', 37), (107, '{READ}', 37), (108, '{UPDATE}', 37), (109, '{DELETE}', 37), "  # nosec B608
            f"(110, '{CREATE}', 38), (111, '{READ}', 38), (112, '{UPDATE}', 38), (113, '{DELETE}', 38), "  # nosec B608
            f"(114, '{CREATE}', 39), (115, '{READ}', 39), (116, '{UPDATE}', 39), (117, '{DELETE}', 39), "  # nosec B608
            f"(118, '{CREATE}', 40), (119, '{READ}', 40), (120, '{UPDATE}', 40), (121, '{DELETE}', 40), "  # nosec B608
            f"(122, '{READ}', 41), (123, '{RUN}', 20), (124, '{RUN}', 21), (125, '{RUN}', 22), "  # nosec B608
            f"(126, '{RUN}', 23), (127, '{RUN}', 38), (128, '{CREATE}', 42), (129, '{READ}', 42), "  # nosec B608
            f"(130, '{DELETE}', 42), (131, '{CREATE}', 43), (132, '{CREATE}', 44), (133, '{READ}', 44), "  # nosec B608
            f"(134, '{UPDATE}', 44), (135, '{DELETE}', 44), (136, '{READ}', 45), (137, '{CREATE}', 46), "  # nosec B608
            f"(138, '{READ}', 46), (139, '{CREATE}', 10), (140, '{UPDATE}', 10), (141, '{DELETE}', 10), "  # nosec B608
            f"(142, '{CREATE}', 9), (147, '{CREATE}', 48), (148, '{READ}', 48), (149, '{UPDATE}', 48), "  # nosec B608
            f"(150, '{DELETE}', 48), (151, '{CREATE}', 49), (152, '{READ}', 49), (153, '{UPDATE}', 49), "  # nosec B608
            f"(154, '{DELETE}', 49), (155, '{CREATE}', 41), (156, '{CREATE}', 50), (157, '{READ}', 50), "  # nosec B608
            f"(158, '{UPDATE}', 50), (159, '{DELETE}', 50), (160, '{TAG}', 40), (161, '{TAG}', 32), "  # nosec B608
            f"(162, '{TAG}', 33), (163, '{TAG}', 26), (164, '{CREATE}', 51), (165, '{READ}', 51), "  # nosec B608
            f"(166, '{UPDATE}', 51), (167, '{DELETE}', 51);"  # nosec B608
        )

        # Insert rows into the 'role_permission' table for the ADMIN role
        db_engine.execute(
            "INSERT INTO role_permission (id, unit_action_id, role_id, allowed) VALUES "
            "(1, 1, 1, true), (2, 2, 1, true), (3, 3, 1, true), (4, 4, 1, true), "
            "(5, 5, 1, true), (6, 6, 1, true), (7, 7, 1, true), (8, 8, 1, true), "
            "(9, 9, 1, true), (10, 10, 1, true), (11, 11, 1, true), (12, 12, 1, true), "
            "(13, 13, 1, true), (14, 14, 1, true), (15, 15, 1, true), (16, 16, 1, true), "
            "(17, 17, 1, true), (18, 18, 1, true), (19, 19, 1, true), (20, 20, 1, true), "
            "(21, 21, 1, true), (22, 22, 1, true), (23, 23, 1, true), (24, 24, 1, true), "
            "(25, 25, 1, true), (26, 26, 1, true), (27, 27, 1, true), (28, 28, 1, true), "
            "(29, 29, 1, true), (30, 30, 1, true), (31, 31, 1, true), (32, 32, 1, true), "
            "(33, 33, 1, true), (34, 34, 1, true), (35, 35, 1, true), (36, 36, 1, true), "
            "(37, 37, 1, true), (38, 38, 1, true), (39, 39, 1, true), (40, 40, 1, true), "
            "(41, 41, 1, true), (42, 42, 1, true), (43, 43, 1, true), (44, 44, 1, true), "
            "(45, 45, 1, true), (46, 46, 1, true), (47, 47, 1, true), "
            "(49, 49, 1, true), (50, 50, 1, true), (51, 51, 1, true), (52, 52, 1, true), "
            "(53, 53, 1, true), (54, 54, 1, true), (55, 55, 1, true), (56, 56, 1, true), "
            "(57, 57, 1, true), (58, 58, 1, true), (59, 59, 1, true), (60, 60, 1, true), "
            "(61, 61, 1, true), (62, 62, 1, true), (63, 63, 1, true), (64, 64, 1, true), "
            "(65, 65, 1, true), (66, 66, 1, true), (67, 67, 1, true), (68, 68, 1, true), "
            "(69, 69, 1, true), (70, 70, 1, true), (71, 71, 1, true), (72, 72, 1, true), "
            "(73, 73, 1, true), (74, 74, 1, true), (75, 75, 1, true), (76, 76, 1, true), "
            "(77, 77, 1, true), (78, 78, 1, true), (79, 79, 1, true), (80, 80, 1, true), "
            "(81, 81, 1, true), (82, 82, 1, true), (83, 83, 1, true), (84, 84, 1, true), "
            "(85, 85, 1, true), (86, 86, 1, true), (87, 87, 1, true), (88, 88, 1, true), "
            "(89, 89, 1, true), (90, 90, 1, true), (91, 91, 1, true), (92, 92, 1, true), "
            "(93, 93, 1, true), (94, 94, 1, true), (95, 95, 1, true), (96, 96, 1, true), "
            "(97, 97, 1, true), (98, 98, 1, true), (99, 99, 1, true), (100, 100, 1, true), "
            "(101, 101, 1, true), (102, 102, 1, true), (103, 103, 1, true), (104, 104, 1, true), "
            "(105, 105, 1, true), (106, 106, 1, true), (107, 107, 1, true), (108, 108, 1, true), "
            "(109, 109, 1, true), (110, 110, 1, true), (111, 111, 1, true), (112, 112, 1, true), "
            "(113, 113, 1, true), (114, 114, 1, true), (115, 115, 1, true), (116, 116, 1, true), "
            "(117, 117, 1, true), (118, 118, 1, true), (119, 119, 1, true), (120, 120, 1, true), "
            "(121, 121, 1, true), (122, 122, 1, true), (489, 123, 1, true), (490, 124, 1, true), "
            "(491, 125, 1, true), (492, 126, 1, true), (493, 127, 1, true), (509, 128, 1, true), "
            "(510, 129, 1, true), (511, 130, 1, true), (521, 131, 1, true), (525, 132, 1, true), "
            "(526, 133, 1, true), (527, 134, 1, true), (528, 135, 1, true), (541, 136, 1, true), "
            "(545, 137, 1, true), (549, 138, 1, true), (553, 139, 1, true), (554, 140, 1, true), "
            "(555, 141, 1, true), (565, 142, 1, true), (585, 147, 1, true), (586, 148, 1, true), "
            "(587, 149, 1, true), (588, 150, 1, true), (601, 151, 1, true), (602, 152, 1, true), "
            "(603, 153, 1, true), (604, 154, 1, true), (617, 155, 1, true), (621, 156, 1, true), "
            "(622, 157, 1, true), (623, 158, 1, true), (624, 159, 1, true), (637, 160, 1, true), "
            "(638, 161, 1, true), (639, 162, 1, true), (640, 163, 1, true), (653, 164, 1, true), "
            "(654, 165, 1, true), (655, 166, 1, true), (656, 167, 1, true);"
        )

        # Insert rows into the 'role_permission' table for the ASSET OWNER role
        db_engine.execute(
            "INSERT INTO role_permission (id, unit_action_id, role_id, allowed) VALUES "
            "(123, 1, 2, false), (124, 2, 2, true), (125, 3, 2, true), (126, 4, 2, false), "
            "(127, 5, 2, false), (128, 6, 2, true), (129, 7, 2, true), (130, 8, 2, true), "
            "(131, 9, 2, true), (132, 10, 2, true), (133, 11, 2, true), (134, 12, 2, true), "
            "(135, 13, 2, true), (136, 14, 2, true), (137, 15, 2, true), (138, 16, 2, true), "
            "(139, 17, 2, true), (140, 18, 2, true), (141, 19, 2, true), (142, 20, 2, true), "
            "(143, 21, 2, true), (144, 22, 2, true), (145, 23, 2, true), (146, 24, 2, true), "
            "(147, 25, 2, true), (148, 26, 2, false), (149, 27, 2, false), (150, 28, 2, false), "
            "(151, 29, 2, false), (152, 30, 2, false), (153, 31, 2, false), (154, 32, 2, false), "
            "(155, 33, 2, false), (156, 34, 2, false), (157, 35, 2, false), (158, 36, 2, false), "
            "(159, 37, 2, false), (160, 38, 2, false), (161, 39, 2, false), (162, 40, 2, false), "
            "(163, 41, 2, false), (164, 42, 2, false), (165, 43, 2, false), (166, 44, 2, true), "
            "(167, 45, 2, false), (168, 46, 2, false), (169, 47, 2, false), "
            "(171, 49, 2, true), (172, 50, 2, false), (173, 51, 2, false), (174, 52, 2, false), "
            "(175, 53, 2, false), (176, 54, 2, false), (177, 55, 2, false), (178, 56, 2, false), "
            "(179, 57, 2, false), (180, 58, 2, false), (181, 59, 2, false), (182, 60, 2, false), "
            "(183, 61, 2, false), (184, 62, 2, false), (185, 63, 2, false), (186, 64, 2, false), "
            "(187, 65, 2, false), (188, 66, 2, false), (189, 67, 2, false), (190, 68, 2, false), "
            "(191, 69, 2, false), (192, 70, 2, false), (193, 71, 2, true), (194, 72, 2, true), "
            "(195, 73, 2, false), (196, 74, 2, false), (197, 75, 2, true), (198, 76, 2, false), "
            "(199, 77, 2, false), (200, 78, 2, false), (201, 79, 2, true), (202, 80, 2, false), "
            "(203, 81, 2, false), (204, 82, 2, true), (205, 83, 2, true), (206, 84, 2, true), "
            "(207, 85, 2, false), (208, 86, 2, false), (209, 87, 2, true), (210, 88, 2, false), "
            "(211, 89, 2, false), (212, 90, 2, false), (213, 91, 2, true), (214, 92, 2, false), "
            "(215, 93, 2, false), (216, 94, 2, false), (217, 95, 2, true), (218, 96, 2, false), "
            "(219, 97, 2, false), (220, 98, 2, false), (221, 99, 2, true), (222, 100, 2, false), "
            "(223, 101, 2, false), (224, 102, 2, false), (225, 103, 2, false), (226, 104, 2, false), "
            "(227, 105, 2, false), (228, 106, 2, true), (229, 107, 2, true), (230, 108, 2, true), "
            "(231, 109, 2, true), (232, 110, 2, false), (233, 111, 2, false), (234, 112, 2, false), "
            "(235, 113, 2, false), (236, 114, 2, false), (237, 115, 2, false), (238, 116, 2, false), "
            "(239, 117, 2, false), (240, 118, 2, false), (241, 119, 2, true), (242, 120, 2, false), "
            "(243, 121, 2, false), (244, 122, 2, false), (494, 123, 2, false), (495, 124, 2, false), "
            "(496, 125, 2, false), (497, 126, 2, false), (498, 127, 2, false), (512, 128, 2, true), "
            "(513, 129, 2, true), (514, 130, 2, true), (522, 131, 2, true), (529, 132, 2, false), "
            "(530, 133, 2, false), (531, 134, 2, false), (532, 135, 2, false), (542, 136, 2, true), "
            "(546, 137, 2, true), (550, 138, 2, true), (556, 139, 2, true), (557, 140, 2, true), "
            "(558, 141, 2, true), (566, 142, 2, true), (589, 147, 2, false), (590, 148, 2, true), "
            "(591, 149, 2, false), (592, 150, 2, false), (605, 151, 2, false), (606, 152, 2, false), "
            "(607, 153, 2, false), (608, 154, 2, false), (618, 155, 2, false), (625, 156, 2, false), "
            "(626, 157, 2, false), (627, 158, 2, false), (628, 159, 2, false), (641, 160, 2, true), "
            "(642, 161, 2, true), (643, 162, 2, true), (644, 163, 2, true), (657, 164, 2, false), "
            "(658, 165, 2, true), (659, 166, 2, true), (660, 167, 2, false);"
        )

        # Insert rows into the 'role_permission' table for the PENTESTER role
        db_engine.execute(
            "INSERT INTO role_permission (id, unit_action_id, role_id, allowed) VALUES "
            "(245, 1, 3, false), (246, 2, 3, true), (247, 3, 3, true), (248, 4, 3, false), "
            "(249, 5, 3, false), (250, 6, 3, true), (251, 7, 3, true), (252, 8, 3, true), "
            "(253, 9, 3, true), (254, 10, 3, true), (255, 11, 3, true), (256, 12, 3, true), "
            "(257, 13, 3, true), (258, 14, 3, true), (259, 15, 3, true), (260, 16, 3, true), "
            "(261, 17, 3, true), (262, 18, 3, true), (263, 19, 3, true), (264, 20, 3, true), "
            "(265, 21, 3, true), (266, 22, 3, true), (267, 23, 3, true), (268, 24, 3, true), "
            "(269, 25, 3, true), (270, 26, 3, true), (271, 27, 3, true), (272, 28, 3, true), "
            "(273, 29, 3, false), (274, 30, 3, true), (275, 31, 3, true), (276, 32, 3, true), "
            "(277, 33, 3, false), (278, 34, 3, true), (279, 35, 3, true), (280, 36, 3, true), "
            "(281, 37, 3, false), (282, 38, 3, true), (283, 39, 3, true), (284, 40, 3, true), "
            "(285, 41, 3, false), (286, 42, 3, true), (287, 43, 3, true), (288, 44, 3, true), "
            "(289, 45, 3, false), (290, 46, 3, true), (291, 47, 3, false), "
            "(293, 49, 3, true), (294, 50, 3, true), (295, 51, 3, true), (296, 52, 3, true), "
            "(297, 53, 3, false), (298, 54, 3, false), (299, 55, 3, false), (300, 56, 3, false), "
            "(301, 57, 3, false), (302, 58, 3, true), (303, 59, 3, true), (304, 60, 3, true), "
            "(305, 61, 3, false), (306, 62, 3, false), (307, 63, 3, false), (308, 64, 3, false), "
            "(309, 65, 3, false), (310, 66, 3, false), (311, 67, 3, false), (312, 68, 3, false), "
            "(313, 69, 3, false), (314, 70, 3, true), (315, 71, 3, true), (316, 72, 3, true), "
            "(317, 73, 3, true), (318, 74, 3, false), (319, 75, 3, true), (320, 76, 3, false), "
            "(321, 77, 3, false), (322, 78, 3, true), (323, 79, 3, true), (324, 80, 3, true), "
            "(325, 81, 3, true), (326, 82, 3, true), (327, 83, 3, true), (328, 84, 3, true), "
            "(329, 85, 3, true), (330, 86, 3, true), (331, 87, 3, true), (332, 88, 3, true), "
            "(333, 89, 3, true), (334, 90, 3, true), (335, 91, 3, true), (336, 92, 3, true), "
            "(337, 93, 3, true), (338, 94, 3, false), (339, 95, 3, true), (340, 96, 3, false), "
            "(341, 97, 3, false), (342, 98, 3, true), (343, 99, 3, true), (344, 100, 3, true), "
            "(345, 101, 3, false), (346, 102, 3, false), (347, 103, 3, false), (348, 104, 3, false), "
            "(349, 105, 3, false), (350, 106, 3, true), (351, 107, 3, true), (352, 108, 3, true), "
            "(353, 109, 3, true), (354, 110, 3, false), (355, 111, 3, false), (356, 112, 3, false), "
            "(357, 113, 3, false), (358, 114, 3, false), (359, 115, 3, false), (360, 116, 3, false), "
            "(361, 117, 3, false), (362, 118, 3, false), (363, 119, 3, true), (364, 120, 3, false), "
            "(365, 121, 3, false), (366, 122, 3, false), (499, 123, 3, true), (500, 124, 3, false), "
            "(501, 125, 3, true), (502, 126, 3, false), (503, 127, 3, false), (515, 128, 3, true), "
            "(516, 129, 3, true), (517, 130, 3, true), (523, 131, 3, true), (533, 132, 3, true), "
            "(534, 133, 3, true), (535, 134, 3, true), (536, 135, 3, true), (543, 136, 3, true), "
            "(547, 137, 3, true), (551, 138, 3, true), (559, 139, 3, true), (560, 140, 3, true), "
            "(561, 141, 3, true), (567, 142, 3, true), (593, 147, 3, true), (594, 148, 3, true), "
            "(595, 149, 3, true), (596, 150, 3, true), (609, 151, 3, false), (610, 152, 3, false), "
            "(611, 153, 3, false), (612, 154, 3, false), (619, 155, 3, false), (629, 156, 3, false), "
            "(630, 157, 3, false), (631, 158, 3, false), (632, 159, 3, false), (645, 160, 3, true), "
            "(646, 161, 3, true), (647, 162, 3, true), (648, 163, 3, true), (661, 164, 3, false), "
            "(662, 165, 3, true), (663, 166, 3, true), (664, 167, 3, false);"
        )

        # Insert rows into the 'role_permission' table for the CLIENT role
        db_engine.execute(
            "INSERT INTO role_permission (id, unit_action_id, role_id, allowed) VALUES "
            "(367, 1, 4, false), (368, 2, 4, true), (369, 3, 4, true), (370, 4, 4, false), "
            "(371, 5, 4, false), (372, 6, 4, true), (373, 7, 4, true), (374, 8, 4, true), "
            "(375, 9, 4, true), (376, 10, 4, true), (377, 11, 4, true), (378, 12, 4, true), "
            "(379, 13, 4, true), (380, 14, 4, true), (381, 15, 4, true), (382, 16, 4, true), "
            "(383, 17, 4, true), (384, 18, 4, true), (385, 19, 4, true), (386, 20, 4, true), "
            "(387, 21, 4, true), (388, 22, 4, true), (389, 23, 4, true), (390, 24, 4, true), "
            "(391, 25, 4, true), (392, 26, 4, false), (393, 27, 4, false), (394, 28, 4, false), "
            "(395, 29, 4, false), (396, 30, 4, false), (397, 31, 4, false), (398, 32, 4, false), "
            "(399, 33, 4, false), (400, 34, 4, false), (401, 35, 4, false), (402, 36, 4, false), "
            "(403, 37, 4, false), (404, 38, 4, false), (405, 39, 4, false), (406, 40, 4, false), "
            "(407, 41, 4, false), (408, 42, 4, false), (409, 43, 4, false), (410, 44, 4, false), "
            "(411, 45, 4, false), (412, 46, 4, false), (413, 47, 4, false), "
            "(415, 49, 4, true), (416, 50, 4, false), (417, 51, 4, false), (418, 52, 4, false), "
            "(419, 53, 4, false), (420, 54, 4, false), (421, 55, 4, false), (422, 56, 4, false), "
            "(423, 57, 4, false), (424, 58, 4, false), (425, 59, 4, false), (426, 60, 4, false), "
            "(427, 61, 4, false), (428, 62, 4, false), (429, 63, 4, false), (430, 64, 4, false), "
            "(431, 65, 4, false), (432, 66, 4, false), (433, 67, 4, false), (434, 68, 4, false), "
            "(435, 69, 4, false), (436, 70, 4, false), (437, 71, 4, true), (438, 72, 4, false), "
            "(439, 73, 4, false), (440, 74, 4, false), (441, 75, 4, true), (442, 76, 4, false), "
            "(443, 77, 4, false), (444, 78, 4, false), (445, 79, 4, true), (446, 80, 4, false), "
            "(447, 81, 4, false), (448, 82, 4, true), (449, 83, 4, true), (450, 84, 4, false), "
            "(451, 85, 4, false), (452, 86, 4, false), (453, 87, 4, true), (454, 88, 4, false), "
            "(455, 89, 4, false), (456, 90, 4, false), (457, 91, 4, true), (458, 92, 4, false), "
            "(459, 93, 4, false), (460, 94, 4, false), (461, 95, 4, true), (462, 96, 4, false), "
            "(463, 97, 4, false), (464, 98, 4, false), (465, 99, 4, true), (466, 100, 4, false), "
            "(467, 101, 4, false), (468, 102, 4, false), (469, 103, 4, false), (470, 104, 4, false), "
            "(471, 105, 4, false), (472, 106, 4, true), (473, 107, 4, true), (474, 108, 4, true), "
            "(475, 109, 4, true), (476, 110, 4, false), (477, 111, 4, false), (478, 112, 4, false), "
            "(479, 113, 4, false), (480, 114, 4, false), (481, 115, 4, false), (482, 116, 4, false), "
            "(483, 117, 4, false), (484, 118, 4, false), (485, 119, 4, true), (486, 120, 4, false), "
            "(487, 121, 4, false), (488, 122, 4, false), (504, 123, 4, false), (505, 124, 4, false), "
            "(506, 125, 4, false), (507, 126, 4, false), (508, 127, 4, false), (518, 128, 4, true), "
            "(519, 129, 4, true), (520, 130, 4, true), (524, 131, 4, true), (537, 132, 4, false), "
            "(538, 133, 4, false), (539, 134, 4, false), (540, 135, 4, false), (544, 136, 4, true), "
            "(548, 137, 4, true), (552, 138, 4, true), (562, 139, 4, true), (563, 140, 4, true), "
            "(564, 141, 4, true), (568, 142, 4, true), (597, 147, 4, false), (598, 148, 4, true), "
            "(599, 149, 4, false), (600, 150, 4, false), (613, 151, 4, false), (614, 152, 4, false), "
            "(615, 153, 4, false), (616, 154, 4, false), (620, 155, 4, false), (633, 156, 4, false), "
            "(634, 157, 4, false), (635, 158, 4, false), (636, 159, 4, false), (649, 160, 4, false), "
            "(650, 161, 4, false), (651, 162, 4, false), (652, 163, 4, false), (665, 164, 4, false), "
            "(666, 165, 4, true), (667, 166, 4, true), (668, 167, 4, false);"
        )

        db_engine.execute(
            "SELECT setval('role_permission_id_seq', (SELECT MAX(id) FROM role_permission));"
        )

        db_engine.execute(
            "SELECT setval('faraday_role_id_seq', (SELECT MAX(id) FROM faraday_role));"
        )

        db_engine.execute(
            "SELECT setval('permissions_unit_action_id_seq', (SELECT MAX(id) FROM permissions_unit_action));"
        )

        db_engine.execute(
            "SELECT setval('permissions_unit_id_seq', (SELECT MAX(id) FROM permissions_unit));"
        )

        db_engine.execute(
            "SELECT setval('permissions_group_id_seq', (SELECT MAX(id) FROM permissions_group));"
        )
    except IntegrityError as e:
        pass
