#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Arena utils module.

    Monster Hunter 3 Server Project
    Copyright (C) 2023  Ze SpyRo

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""
Arena Quest ID List:
EA60 
EA61
EA62
EA63
EA64
EA65
EA66
EA67
EA68
EA69
EA6A
EA6B
"""

# bird and brute bowgun: rathling gun + barrel, poison stinger frame, light bowgun stock
# sea power bowgun: rathling gun barrel, rathling gun + frame, rathling gun + stock
# land lords bowgun: jho barrel, diablos frame, barioth stock
# two flames bowgun: lagiacrus barrel, lagiacrus frame, barioth stock

import csv
from mh.quest_utils import make_binary_event_quest,\
    generate_flags, Monster, LocationType,\
    QuestRankType, QuestRestrictionType, ResourcesType,\
    StartingPositionType, ItemsType
from mh.equipment_utils import Chestpiece, Gauntlets, Faulds,\
    Leggings, Helmet, EquipmentClasses, Greatsword,\
    SnS, Hammer, Longsword, Switchaxe, Lance,\
    BowgunFrame, BowgunStock, BowgunBarrel


GRUDGE_MATCH_ROYAL_LUDROTH = {
    'quest_info': {
        'quest_id': 0xEA61,
        'name': "Grudge Match: Royal Ludroth",
        'client': "Announcer/Receptionist",
        'description': "Slay a Royal Ludroth",
        'details': "Wanted:" + '\x0A' + "The description for this" + '\x0A' +
            "quest! If you can find" + '\x0A' + "it, please let us know!" + '\x0A' +
            "Thanks!",
        'success_message': "Complete the Main Quest.",
        'flags': generate_flags((0,0,0,0,0,1,0,0),(1,0,0,0,1,0,0,0),(0,0,0,0,0,0,0,0),(1,0,0,0,1,0,1,0)),
        'penalty_per_cart': 350,
        'quest_fee': 0,
        'time_limit': 50,
        'main_monster_1': Monster.none,
        'main_monster_2': Monster.none,
        'location': LocationType.QUEST_LOCATION_WATER_ARENA_2,
        'quest_rank':QuestRankType.star_1,
        'hrp_restriction': QuestRestrictionType.RESTRICTION_NONE,
        'resources': ResourcesType.arena,
        'supply_set_number': 0,
        'starting_position': StartingPositionType.camp, 
        'general_enemy_level': 0x0017,
        'summon': 0x00000000,
        'smallmonster_data_file': 'sm_underwaterarenarock.dat',
    },
    'large_monsters': {
        'monster_1': {
            'type': Monster.royal_ludroth,
            'boss_id': 0x0000,
            'enabled': True,
            'level': 0x17,  # 0x01 through 0x3c
            'size': 0x64,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        },
        'monster_2': {
            'type': Monster.none,
            'boss_id': 0x0000,
            'enabled': False,
            'level': 0x00,  # 0x01 through 0x3c
            'size': 0x00,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        },
        'monster_3': {
            'type': Monster.none,
            'boss_id': 0x0000,
            'enabled': False,
            'level': 0x00,  # 0x01 through 0x3c
            'size': 0x00,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        }
    },
    'objective_details': {
        'main_quest': {
            'type': 0x00000101,
            'objective_type': Monster.royal_ludroth,
            'objective_num': 0x01,
            'zenny_reward': 1000,
            'hrp_reward': 0,
            'rewards_row_1': [(ItemsType.r_ludroth_coin, 1, 24), (ItemsType.r_ludroth_coin, 2, 8),
                              (ItemsType.voucher, 1, 10), (ItemsType.armor_sphere, 1, 24),
                              (ItemsType.steel_eg, 1, 18), (ItemsType.pinnacle_coin, 1, 16)],
            'rewards_row_2': [],
        },
        'subquest_1': {
            'description': "None",
            'type': 0x00000000,
            'objective_type': Monster.none,
            'objective_num': 0x00,
            'zenny_reward': 0,
            'hrp_reward': 0x00000000,
            'rewards_row_1': [],
        },
        'subquest_2': {
            'description': "None",
            'type': 0x00000000,
            'objective_type': Monster.none,
            'objective_num': 0x00,
            'zenny_reward': 0,
            'hrp_reward': 0x00000000,
            'rewards_row_1': [],
        },
    },
    'unknown': {
        'unk_12': 0x00000002,  # 2 for large mon quest, 3 for small/delivery, 5 for jhen/ala
        'unk_4': 0x00,
        'unk_5': 0x00,
        'unk_6': 0x00,
        'unk_7': 0x00000000,
        'unk_9': 0x00000000,
        'unk_10': 0x00000000,
        'unk_11': 0x00000000,
    },
    'arena_equipment': (\
        ((EquipmentClasses.SnS, SnS.HydraKnife), None, None,
            Helmet.QurupecoHelm, Chestpiece.QurupecoMail, Gauntlets.BlastBracelet, Faulds.SteelFaulds, Leggings.IngotGreaves,
            ((ItemsType.whetstone, 20), (ItemsType.potion, 10), (ItemsType.ration, 10), (ItemsType.oxygen_supply, 10), (ItemsType.lifepowder, 2),
                (ItemsType.barrel_bomb_l, 3), (ItemsType.barrel_bomb_s, 10)),
            ()),
        ((EquipmentClasses.Greatsword, Greatsword.ChieftainsGrtSwd), None, None,
            Helmet.DrawEarring, Chestpiece.SteelMail, Gauntlets.GobulVambraces, Faulds.GobulFaulds, Leggings.HuntersGreaves,
            ((ItemsType.whetstone, 20), (ItemsType.potion, 10), (ItemsType.ration, 10), (ItemsType.oxygen_supply, 10), (ItemsType.might_pill, 2),
                (ItemsType.shock_trap, 1), (ItemsType.ez_flash_bomb, 1)),
            ()),
        ((EquipmentClasses.Hammer, Hammer.BoneBludgeon), None, None,
            Helmet.BarrothHelm, Chestpiece.BarrothMail, Gauntlets.AlloyVambraces, Faulds.BarrothFaulds, Leggings.BarrothGreaves,
            ((ItemsType.whetstone, 20), (ItemsType.potion, 10), (ItemsType.ration, 10), (ItemsType.oxygen_supply, 10), (ItemsType.paralysis_knife, 5),
                (ItemsType.ez_flash_bomb, 1)),
            ()),
        ((EquipmentClasses.BowgunFrame, BowgunFrame.RoyalLauncher), (EquipmentClasses.BowgunBarrel, BowgunBarrel.JaggidFire), (EquipmentClasses.BowgunStock, BowgunStock.LightBowgun),
            Helmet.AlloyCap, Chestpiece.AlloyVest, Gauntlets.LagiacrusGuards, Faulds.AlloyCoat, Leggings.PiscineLeggings,
            ((ItemsType.potion, 10), (ItemsType.ration, 10), (ItemsType.oxygen_supply, 10), (ItemsType.lifepowder, 2), (ItemsType.shock_trap, 1),
                (ItemsType.barrel_bomb_l_plus, 2), (ItemsType.barrel_bomb_l, 2)),
            ((ItemsType.normal_s_lv2, 99), (ItemsType.pierce_s_lv1, 60), (ItemsType.pierce_s_lv2, 50), (ItemsType.clust_s_lv1, 5),
                (ItemsType.poison_s_lv1, 12), (ItemsType.para_s_lv1, 12))))
}

GRUDGE_MATCH_BIRD_BRUTE = {
    'quest_info': {
        'quest_id': 0xEA66,
        'name': "Grudge Match: Bird and Brute",
        'client': "Announcer/Receptionist",
        'description': "Slay a Qurupeco" + '\x0A' + "and a Barroth",
        'details': "Wanted:" + '\x0A' + "The description for this" + '\x0A' +
            "quest! If you can find" + '\x0A' + "it, please let us know!" + '\x0A' +
            "Thanks!",
        'success_message': "Complete the Main Quest.",
        'flags': generate_flags((0,1,0,0,0,1,0,0),(1,0,0,0,1,0,0,0),(0,0,0,0,0,0,0,0),(1,0,0,0,1,0,1,0)),
        'penalty_per_cart': 350,
        'quest_fee': 0,
        'time_limit': 50,
        'main_monster_1': Monster.none,
        'main_monster_2': Monster.none,
        'location': LocationType.QUEST_LOCATION_LAND_ARENA_1,
        'quest_rank': QuestRankType.star_4,
        'hrp_restriction': QuestRestrictionType.RESTRICTION_31_INITJOIN,
        'resources': ResourcesType.arena,
        'supply_set_number': 0,
        'starting_position': StartingPositionType.camp, 
        'general_enemy_level': 0x0017,
        'summon': 0x00000000,
        'smallmonster_data_file': 'sm_bloodsport.dat',
    },
    'large_monsters': {
        'monster_1': {
            'type': Monster.qurupeco,
            'boss_id': 0x0000,
            'enabled': True,
            'level': 0x17,  # 0x01 through 0x3c
            'size': 0x64,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        },
        'monster_2': {
            'type': Monster.barroth,
            'boss_id': 0x0001,
            'enabled': True,
            'level': 0x17,  # 0x01 through 0x3c
            'size': 0x64,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        },
        'monster_3': {
            'type': Monster.none,
            'boss_id': 0x0000,
            'enabled': False,
            'level': 0x00,  # 0x01 through 0x3c
            'size': 0x00,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        }
    },
    'objective_details': {
        'main_quest': {
            'type': 0x00000101,
            'objective_type': Monster.qurupeco,
            'objective_num': 0x01,
            'zenny_reward': 1000,
            'hrp_reward': 0,
            'rewards_row_1': [(ItemsType.qurupeco_coin, 1, 16), (ItemsType.barroth_coin, 1, 20),
                              (ItemsType.voucher, 1, 14), (ItemsType.armor_sphere_plus, 1, 10),
                              (ItemsType.adv_armor_sphere, 1, 5), (ItemsType.steel_eg, 1, 15),
                              (ItemsType.silver_eg, 1, 5), (ItemsType.hunter_king_coin, 1, 15)],
            'rewards_row_2': [],
        },
        'subquest_1': {
            'description': "None",
            'type': 0x00000101,
            'objective_type': Monster.barroth,
            'objective_num': 0x01,
            'zenny_reward': 0,
            'hrp_reward': 0x00000000,
            'rewards_row_1': [],
        },
        'subquest_2': {
            'description': "None",
            'type': 0x00000000,
            'objective_type': Monster.none,
            'objective_num': 0x00,
            'zenny_reward': 0,
            'hrp_reward': 0x00000000,
            'rewards_row_1': [],
        },
    },
    'unknown': {
        'unk_12': 0x00000002,  # 2 for large mon quest, 3 for small/delivery, 5 for jhen/ala
        'unk_4': 0x00,
        'unk_5': 0x00,
        'unk_6': 0x00,
        'unk_7': 0x00000000,
        'unk_9': 0x00000000,
        'unk_10': 0x00000000,
        'unk_11': 0x00000000,
    },
    'arena_equipment': (\
        ((EquipmentClasses.Switchaxe, Switchaxe.AssaultAxePlus), None, None,
            Helmet.GigginoxCapPlus, Chestpiece.AlloyMail, Gauntlets.BaggiVambracesPlus, Faulds.GigginoxFauldsPlus, Leggings.GigginoxGreaves,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.whetstone, 20), (ItemsType.ration, 10), (ItemsType.cleanser, 5),
                (ItemsType.barrel_bomb_l, 2), (ItemsType.lifepowder, 1), (ItemsType.ez_shock_trap, 1), (ItemsType.ez_flash_bomb, 2)),
            ()),
        ((EquipmentClasses.Greatsword, Greatsword.CataclysmSword), None, None,
            Helmet.DrawEarring, Chestpiece.JaggiMailPlus, Gauntlets.JaggiVambracesPlus, Faulds.JaggiFauldsPlus, Leggings.BoneGreavesPlus,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.whetstone, 20), (ItemsType.ration, 10), (ItemsType.cleanser, 5),
                (ItemsType.barrel_bomb_l, 3), (ItemsType.barrel_bomb_s, 2), (ItemsType.pitfall_trap, 1), (ItemsType.ez_flash_bomb, 2)),
            ()),
        ((EquipmentClasses.Lance, Lance.Undertaker), None, None,
            Helmet.DiablosCap, Chestpiece.AgnaktorMailPlus, Gauntlets.SteelVambracesPlus, Faulds.SteelCoilPlus, Leggings.AlloyGreaves,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.whetstone, 20), (ItemsType.ration, 10), (ItemsType.cleanser, 5),
                (ItemsType.barrel_bomb_l, 2), (ItemsType.ez_flash_bomb, 1)),
            ()),
        ((EquipmentClasses.BowgunFrame, BowgunFrame.PoisonStinger), (EquipmentClasses.BowgunBarrel, BowgunBarrel.RathlingGunPlus), (EquipmentClasses.BowgunStock, BowgunStock.LightBowgun),
            Helmet.AgnaktorCapPlus, Chestpiece.AgnaktorVestPlus, Gauntlets.AgnaktorGuardsPlus, Faulds.AgnaktorCoatPlus, Leggings.RathalosLeggingsPlus,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.ration, 10), (ItemsType.cleanser, 5), (ItemsType.lifepowder, 2),
                (ItemsType.ez_flash_bomb, 1), (ItemsType.sonic_bomb, 2)),
            ((ItemsType.normal_s_lv2, 99), (ItemsType.normal_s_lv3, 99), (ItemsType.pierce_s_lv2, 50), (ItemsType.clust_s_lv2, 5),
                (ItemsType.crag_s_lv2, 9), (ItemsType.poison_s_lv1, 12), (ItemsType.para_s_lv1, 12), (ItemsType.sleep_s_lv1, 12))))
}


GRUDGE_MATCH_TWO_FLAMES = {
    'quest_info': {
        'quest_id': 0xEA68,
        'name': "Grudge Match: Two Flames",
        'client': "Announcer/Receptionist",
        'description': "Slay a Rathalos" + '\x0A' + "and a Rathian",
        'details': "Wanted:" + '\x0A' + "The description for this" + '\x0A' +
            "quest! If you can find" + '\x0A' + "it, please let us know!" + '\x0A' +
            "Thanks!",
        'success_message': "Complete the Main Quest.",
        'flags': generate_flags((0,1,0,0,0,1,0,0),(1,0,0,0,1,0,0,0),(0,0,0,0,0,0,0,0),(1,0,0,0,1,0,1,0)),
        'penalty_per_cart': 350,
        'quest_fee': 0,
        'time_limit': 50,
        'main_monster_1': Monster.none,
        'main_monster_2': Monster.none,
        'location': LocationType.QUEST_LOCATION_LAND_ARENA_1,
        'quest_rank': QuestRankType.star_5,
        'hrp_restriction': QuestRestrictionType.RESTRICTION_31_INITJOIN,
        'resources': ResourcesType.arena,
        'supply_set_number': 0,
        'starting_position': StartingPositionType.camp, 
        'general_enemy_level': 0x0017,
        'summon': 0x00000000,
        'smallmonster_data_file': 'sm_bloodsport.dat',
    },
    'large_monsters': {
        'monster_1': {
            'type': Monster.rathalos,
            'boss_id': 0x0000,
            'enabled': True,
            'level': 0x17,  # 0x01 through 0x3c
            'size': 0x64,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        },
        'monster_2': {
            'type': Monster.rathian,
            'boss_id': 0x0001,
            'enabled': True,
            'level': 0x17,  # 0x01 through 0x3c
            'size': 0x64,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        },
        'monster_3': {
            'type': Monster.none,
            'boss_id': 0x0000,
            'enabled': False,
            'level': 0x00,  # 0x01 through 0x3c
            'size': 0x00,
            'hp_spread': 0x00, # 0: fixed, 1: spread of 5, 2: spread of 3
            'size_spread': 0x00  # controls the spread of size but details unknown
        }
    },
    'objective_details': {
        'main_quest': {
            'type': 0x00000101,
            'objective_type': Monster.rathalos,
            'objective_num': 0x01,
            'zenny_reward': 1000,
            'hrp_reward': 0,
            'rewards_row_1': [(ItemsType.rathalos_coin, 1, 10), (ItemsType.rathian_coin, 1, 24),
                              (ItemsType.voucher, 1, 14), (ItemsType.armor_sphere_plus, 1, 10),
                              (ItemsType.adv_armor_sphere, 1, 5), (ItemsType.steel_eg, 1, 15),
                              (ItemsType.silver_eg, 1, 5), (ItemsType.hunter_king_coin, 1, 17)],
            'rewards_row_2': [],
        },
        'subquest_1': {
            'description': "None",
            'type': 0x00000101,
            'objective_type': Monster.rathian,
            'objective_num': 0x01,
            'zenny_reward': 0,
            'hrp_reward': 0x00000000,
            'rewards_row_1': [],
        },
        'subquest_2': {
            'description': "None",
            'type': 0x00000000,
            'objective_type': Monster.none,
            'objective_num': 0x00,
            'zenny_reward': 0,
            'hrp_reward': 0x00000000,
            'rewards_row_1': [],
        },
    },
    'unknown': {
        'unk_12': 0x00000002,  # 2 for large mon quest, 3 for small/delivery, 5 for jhen/ala
        'unk_4': 0x00,
        'unk_5': 0x00,
        'unk_6': 0x00,
        'unk_7': 0x00000000,
        'unk_9': 0x00000000,
        'unk_10': 0x00000000,
        'unk_11': 0x00000000,
    },
    'arena_equipment': (\
        ((EquipmentClasses.SnS, SnS.IcicleSpikePlus), None, None,
            Helmet.QurupecoHelmPlus, Chestpiece.QurupecoMailPlus, Gauntlets.QurupecoVambracesPlus, Faulds.QurupecoCoilPlus, Leggings.QurupecoGreavesPlus,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.whetstone, 20), (ItemsType.ration, 10), (ItemsType.might_pill, 2),
                (ItemsType.antidote, 2), (ItemsType.lifepowder, 1), (ItemsType.dung_bomb, 1), (ItemsType.paralysis_knife, 5),
                (ItemsType.pitfall_trap, 1), (ItemsType.ez_flash_bomb, 5), (ItemsType.barrel_bomb_l_plus, 1), (ItemsType.barrel_bomb_s, 1)),
            ()),
        ((EquipmentClasses.Longsword, Longsword.Thunderclap), None, None,
            Helmet.SilenceEarring, Chestpiece.AlloyMailPlus, Gauntlets.SteelVambracesPlus, Faulds.SteelCoilPlus, Leggings.VangisGreaves,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.whetstone, 20), (ItemsType.ration, 10), (ItemsType.antidote, 2),
                (ItemsType.lifepowder, 1), (ItemsType.dung_bomb, 1), (ItemsType.ez_flash_bomb, 2)),
            ()),
        ((EquipmentClasses.Lance, Lance.SpiralLancePlus), None, None,
            Helmet.DemonEdgeEarring, Chestpiece.IngotMailPlus, Gauntlets.AgnaktorVambracesPlus, Faulds.RhenoplosCoilPlus, Leggings.IngotGreavesPlus,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.whetstone, 20), (ItemsType.well_done_steak, 10), (ItemsType.antidote, 2),
                (ItemsType.lifepowder, 1), (ItemsType.dung_bomb, 1), (ItemsType.poison_knife, 5), (ItemsType.shock_trap, 1), (ItemsType.ez_flash_bomb, 1)),
            ()),
        ((EquipmentClasses.BowgunFrame, BowgunFrame.ThundacrusRex), (EquipmentClasses.BowgunBarrel, BowgunBarrel.ThundacrusRex), (EquipmentClasses.BowgunStock, BowgunStock.BlizzardCannon),
            Helmet.EarringofFate, Chestpiece.UragaanVestPlus, Gauntlets.BlastBracelet, Faulds.UragaanCoatPlus, Leggings.UragaanLeggingsPlus,
            ((ItemsType.potion, 10), (ItemsType.mega_potion, 10), (ItemsType.ration, 10), (ItemsType.antidote, 2), (ItemsType.lifepowder, 2),
                (ItemsType.dung_bomb, 1), (ItemsType.shock_trap, 1), (ItemsType.ez_shock_trap, 1), (ItemsType.pitfall_trap, 1), (ItemsType.ez_barrel_bomb_l, 1),
                (ItemsType.barrel_bomb_l, 3), (ItemsType.barrel_bomb_s, 10)),
            ((ItemsType.normal_s_lv2, 99), (ItemsType.normal_s_lv3, 99), (ItemsType.pierce_s_lv3, 40), (ItemsType.demon_s_ii, 5), (ItemsType.thunder_s, 60))))
}
