package edu.programmAllan.payments_control.service;

import edu.programmAllan.payments_control.entity.ParticipantInfo;
import edu.programmAllan.payments_control.entity.enums.ParticipantStatus;
import edu.programmAllan.payments_control.repository.ParticipantInfoRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class ParticipantInfoServiceTest {


    @Mock
    private ParticipantInfoRepository participantInfoRepository;


    @InjectMocks
    private ParticipantInfoService participantInfoService;

    private ParticipantInfo participantInfo;

    @BeforeEach
    public void setup() {
        participantInfo = new ParticipantInfo();
        participantInfo.setId(1);
        participantInfo.setName("User Name");
        participantInfo.setEmail("user@email.com");
        participantInfo.setPhoneNumber(new BigInteger("73999999999"));
        participantInfo.setStatus(ParticipantStatus.ACTIVE);
    }

    @Test
    @DisplayName("Should save a new participant")
    void sucessInSaveAParticipant() {
        // Configura o mock para o repositório
        when(participantInfoRepository.save(any(ParticipantInfo.class))).thenAnswer(invocation -> invocation.getArgument(0));


        // Chama o metodo real no serviço
        ParticipantInfo savedParticipant = participantInfoService.save(participantInfo);

        // Verifica a interação com o repositório, não com o serviço diretamente
        verify(participantInfoRepository).save(any());

        // Assegura que os dados do participante salvos estão corretos
        assertAll("Check saved participant data",
                () -> assertEquals(participantInfo.getName(), savedParticipant.getName()),
                () -> assertEquals(participantInfo.getEmail(), savedParticipant.getEmail()),
                () -> assertEquals(participantInfo.getPhoneNumber(), savedParticipant.getPhoneNumber()),
                () -> assertEquals(participantInfo.getStatus(), savedParticipant.getStatus())
        );
    }

    @Test
    @DisplayName("Should throws a error when save a participant")
    void errorInSaveAParticipant() {
        when(participantInfoRepository.save(any())).thenReturn(new Exception());

        assertThrows(RuntimeException.class, () -> participantInfoService.save(participantInfo));

        verify(participantInfoRepository).save(any());

    }
}