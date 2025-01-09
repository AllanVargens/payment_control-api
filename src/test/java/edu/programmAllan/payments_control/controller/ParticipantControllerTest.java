package edu.programmAllan.payments_control.controller;

import edu.programmAllan.payments_control.entity.ParticipantInfo;
import edu.programmAllan.payments_control.entity.enums.ParticipantStatus;
import edu.programmAllan.payments_control.exceptions.NoSuchExistsException;
import edu.programmAllan.payments_control.service.ParticipantInfoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
@SpringBootTest
class ParticipantControllerTest {

    private MockMvc mockMvc;

    private ParticipantInfo participantInfo;

    @Autowired
    private WebApplicationContext context;

    @MockitoBean
    ParticipantInfoService participantInfoService;

    @InjectMocks
    ParticipantController participantController;

    List<ParticipantInfo> participants = new ArrayList<ParticipantInfo>();

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();

        ParticipantInfo participant1 = new ParticipantInfo();
        participant1.setId(1);
        participant1.setName("User Name");
        participant1.setEmail("user@email.com");
        participant1.setPhoneNumber(new BigInteger("73999999999"));
        participant1.setStatus(ParticipantStatus.ACTIVE);

        ParticipantInfo participant2 = new ParticipantInfo();
        participant2.setId(2);
        participant2.setName("User Name 2");
        participant2.setEmail("user2@email.com");
        participant2.setPhoneNumber(new BigInteger("73888888888"));
        participant2.setStatus(ParticipantStatus.ACTIVE);

        ParticipantInfo participant3 = new ParticipantInfo();
        participant3.setId(3);
        participant3.setName("Test Diferent Name");
        participant3.setEmail("test@email.com");
        participant3.setPhoneNumber(new BigInteger("73888834888"));
        participant3.setStatus(ParticipantStatus.ACTIVE);

        participants.add(participant1);
        participants.add(participant2);
        participants.add(participant3);
    }

    @Test
    @DisplayName("Shold be return all participants with the respective name")
    @WithMockUser(username = "admin", password = "admin", authorities = "ADMIN")
    void userPresentInDB() throws Exception {

        List<ParticipantInfo> expectedParticipants = new ArrayList<>();
        for (ParticipantInfo participant : participants) {
            if (participant.getName().contains("User")) {
                expectedParticipants.add(participant);
            }
        }

        when(participantInfoService.findByName("User")).thenReturn(expectedParticipants);

        ResultActions result = mockMvc.perform(get("/participants/find?name=User")).andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$", hasSize(expectedParticipants.size())));

        for (int i = 0; i < expectedParticipants.size(); i++) {
            ParticipantInfo participant = expectedParticipants.get(i);
            result.andExpect(jsonPath("$[" + i + "].id").value(participant.getId()));
            result.andExpect(jsonPath("$[" + i + "].name").value(participant.getName()));
            result.andExpect(jsonPath("$[" + i + "].email").value(participant.getEmail()));
            result.andExpect(jsonPath("$[" + i + "].phoneNumber").value(participant.getPhoneNumber().toString()));
            result.andExpect(jsonPath("$[" + i + "].status").value(participant.getStatus().toString()));
        }
    }

    @Test
    @DisplayName("Shold be return a error because dont have the respectives participants in DB")
    @WithMockUser(username = "admin", password = "admin", authorities = "ADMIN")
    void userNotPresentInDB() throws Exception {

        String name = "Unknown Participant";
        List<ParticipantInfo> participants = new ArrayList<>();

        // Configura o comportamento do serviço mockado
        when(participantInfoService.findByName(name)).thenReturn(participants);

        // Quando & Então
        ResultActions result = mockMvc.perform(get("/participants/findByName")
                        .param("name", name))
                .andExpect(status().isNotFound());

    }

//    @Test
//    void findAll() {
//    }
//
//    @Test
//    void addParticipant() {
//    }
//
//    @Test
//    void removeParticipant() {
//    }
}